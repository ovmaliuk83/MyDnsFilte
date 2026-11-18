package com.example.dnsfilter

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Color
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import java.util.concurrent.Executors

data class AppItem(
    val name: String,
    val packageName: String,
    var isExcluded: Boolean
) {
    // Считаем один раз, а не при каждом символе поиска
    val searchKey: String = "$name $packageName".lowercase()
}

class MainActivity : AppCompatActivity() {

    private lateinit var adapter: AppsAdapter
    private lateinit var btnStart: Button
    private lateinit var btnStop: Button
    private lateinit var btnQueries: Button
    private lateinit var tvStats: TextView

    private var allApps: List<AppItem> = emptyList()
    private var currentQuery = ""
    private val excluded = mutableSetOf<String>()
    private var shownRunningState: Boolean? = null

    private val handler = Handler(Looper.getMainLooper())
    private val ioExecutor = Executors.newSingleThreadExecutor()

    // Раз в секунду обновляем счётчики и состояние кнопок
    private val ticker = object : Runnable {
        override fun run() {
            refreshUi()
            handler.postDelayed(this, 1000)
        }
    }

    private val vpnLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) startFilter()
    }

    private val notificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* без уведомления сервис всё равно работает */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        btnStart = findViewById(R.id.btnStart)
        btnStop = findViewById(R.id.btnStop)
        tvStats = findViewById(R.id.tvStats)
        btnQueries = findViewById(R.id.btnQueries)
        val searchBar = findViewById<EditText>(R.id.searchBar)
        val recyclerView = findViewById<RecyclerView>(R.id.recyclerApps)

        FilterStats.init(this)

        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        val prefs = getSharedPreferences("dns_prefs", MODE_PRIVATE)
        excluded.addAll(prefs.getStringSet("excluded_apps", emptySet()) ?: emptySet())

        adapter = AppsAdapter(emptyList()) { item, isChecked ->
            if (isChecked) excluded.add(item.packageName) else excluded.remove(item.packageName)
            prefs.edit().putStringSet("excluded_apps", HashSet(excluded)).apply()
            if (LocalDnsVpnService.isRunning) {
                Toast.makeText(this, "Перезапустите фильтр для применения", Toast.LENGTH_SHORT).show()
            }
        }
        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = adapter

        searchBar.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                currentQuery = s.toString().trim().lowercase()
                adapter.updateList(filterApps())
            }
            override fun afterTextChanged(s: Editable?) {}
        })

        btnStart.setOnClickListener {
            val intent = VpnService.prepare(this)
            if (intent != null) vpnLauncher.launch(intent) else startFilter()
        }

        btnStop.setOnClickListener {
            if (LocalDnsVpnService.isRunning) {
                startService(
                    Intent(this, LocalDnsVpnService::class.java)
                        .setAction(LocalDnsVpnService.ACTION_STOP)
                )
                Toast.makeText(this, "Фильтр остановлен", Toast.LENGTH_SHORT).show()
            }
        }

        btnQueries.setOnClickListener { onQueriesClicked() }

        loadApps()
    }

    private fun startFilter() {
        ContextCompat.startForegroundService(this, Intent(this, LocalDnsVpnService::class.java))
        Toast.makeText(this, "Фильтр запущен", Toast.LENGTH_SHORT).show()
    }

    /** Список приложений собираем в фоне: loadLabel() для сотен приложений тормозит UI. */
    private fun loadApps() {
        val excludedSnapshot = HashSet(excluded)
        ioExecutor.execute {
            val pm = packageManager
            val apps = pm.getInstalledApplications(0)
                .filter {
                    it.packageName != packageName &&
                        pm.checkPermission(Manifest.permission.INTERNET, it.packageName) ==
                        PackageManager.PERMISSION_GRANTED
                }
                .map {
                    AppItem(
                        name = it.loadLabel(pm).toString(),
                        packageName = it.packageName,
                        isExcluded = it.packageName in excludedSnapshot
                    )
                }
                .sortedBy { it.name.lowercase() }

            runOnUiThread {
                if (isDestroyed) return@runOnUiThread
                allApps = apps
                adapter.updateList(filterApps())
            }
        }
    }

    private fun filterApps(): List<AppItem> =
        if (currentQuery.isEmpty()) allApps else allApps.filter { it.searchKey.contains(currentQuery) }

    private fun refreshUi() {
        tvStats.text = "Заблокировано рекламных запросов: ${FilterStats.adsBlocked.get()}\n" +
            "Блокировка системного DNS (DoT): ${FilterStats.dotBlocked.get()}"

        btnQueries.text =
            if (QueryLog.enabled) "Последние запросы (запись идёт)" else "Включить запись запросов"

        val running = LocalDnsVpnService.isRunning
        if (running != shownRunningState) {
            shownRunningState = running
            val green = ColorStateList.valueOf(Color.parseColor("#4CAF50"))
            val gray = ColorStateList.valueOf(Color.GRAY)
            btnStart.isEnabled = !running
            btnStart.backgroundTintList = if (running) gray else green
            btnStop.isEnabled = running
            btnStop.backgroundTintList = if (running) green else gray
        }
    }

    // ───────────────────────── последние запросы ─────────────────────────

    private fun onQueriesClicked() {
        if (!QueryLog.enabled) {
            QueryLog.enabled = true
            Toast.makeText(
                this,
                "Запись включена. Откройте сайт в браузере и вернитесь сюда",
                Toast.LENGTH_LONG
            ).show()
            return
        }
        showQueriesDialog()
    }

    private fun showQueriesDialog() {
        val list = QueryLog.snapshot()
        if (list.isEmpty()) {
            Toast.makeText(
                this,
                "Пока пусто. Фильтр запущен? Защищённый DNS в Chrome выключен?",
                Toast.LENGTH_LONG
            ).show()
            return
        }
        val labels = Array<CharSequence>(list.size) { i ->
            val (domain, blocked) = list[i]
            (if (blocked) "🚫 " else "✅ ") + domain
        }

        AlertDialog.Builder(this)
            .setTitle("Запросы: новые сверху")
            .setItems(labels) { _, which ->
                val (domain, blocked) = list[which]
                if (blocked) {
                    Toast.makeText(this, "Уже заблокирован", Toast.LENGTH_SHORT).show()
                } else {
                    confirmBlock(domain)
                }
            }
            .setPositiveButton("Закрыть", null)
            .setNegativeButton("Остановить и очистить") { _, _ ->
                QueryLog.enabled = false
                QueryLog.clear()
            }
            .show()
    }

    private fun confirmBlock(domain: String) {
        AlertDialog.Builder(this)
            .setTitle("Заблокировать?")
            .setMessage(
                "$domain и все его поддомены.\n\n" +
                    "Не блокируйте общие домены (например, yandex.ru или google.com): " +
                    "перестанут работать почта, карты и поиск."
            )
            .setPositiveButton("Заблокировать") { _, _ ->
                val prefs = getSharedPreferences("dns_prefs", MODE_PRIVATE)
                val set = HashSet(prefs.getStringSet("custom_blocked", emptySet()) ?: emptySet())
                set.add(domain)
                prefs.edit().putStringSet("custom_blocked", set).apply()
                LocalDnsVpnService.customBlocked.add(domain)
                Toast.makeText(
                    this,
                    "Добавлено. Перезапустите браузер: он кэширует адреса",
                    Toast.LENGTH_LONG
                ).show()
            }
            .setNegativeButton("Отмена", null)
            .show()
    }

    // ───────────────────────── жизненный цикл ─────────────────────────

    override fun onResume() {
        super.onResume()
        handler.post(ticker)
    }

    override fun onPause() {
        handler.removeCallbacks(ticker)
        FilterStats.save(this)
        super.onPause()
    }

    override fun onDestroy() {
        ioExecutor.shutdown()
        super.onDestroy()
    }
}

class AppsAdapter(
    private var items: List<AppItem>,
    private val onToggle: (AppItem, Boolean) -> Unit
) : RecyclerView.Adapter<AppsAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val checkBox: CheckBox = view as CheckBox
    }

    fun updateList(newItems: List<AppItem>) {
        items = newItems
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val checkBox = CheckBox(parent.context).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            setPadding(16, 24, 16, 24)
            textSize = 16f
        }
        return ViewHolder(checkBox)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        holder.checkBox.setOnCheckedChangeListener(null)
        holder.checkBox.text = "${item.name}\n(${item.packageName})"
        holder.checkBox.isChecked = item.isExcluded
        holder.checkBox.setOnCheckedChangeListener { _, isChecked ->
            item.isExcluded = isChecked
            onToggle(item, isChecked)
        }
    }

    override fun getItemCount() = items.size
}
