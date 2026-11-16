package com.example.dnsfilter

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView

data class AppItem(
    val name: String,
    val packageName: String,
    var isExcluded: Boolean
)

class MainActivity : AppCompatActivity() {

    private lateinit var allAppsList: List<AppItem>
    private lateinit var adapter: AppsAdapter
    private lateinit var btnStart: Button
    private lateinit var btnStop: Button

    private val vpnLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startService(Intent(this, LocalDnsVpnService::class.java))
            Toast.makeText(this, "Фильтр запущен", Toast.LENGTH_SHORT).show()
            updateButtonStates(true)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        btnStart = findViewById(R.id.btnStart)
        btnStop = findViewById(R.id.btnStop)
        val searchBar = findViewById<EditText>(R.id.searchBar)

        val prefs = getSharedPreferences("dns_prefs", MODE_PRIVATE)
        val savedExcluded = prefs.getStringSet("excluded_apps", emptySet())?.toMutableSet() ?: mutableSetOf()

        val pm = packageManager
        // Ищем ВСЕ приложения, у которых есть доступ к интернету (включая Chrome)
        allAppsList = pm.getInstalledApplications(0)
            .filter { pm.checkPermission(android.Manifest.permission.INTERNET, it.packageName) == PackageManager.PERMISSION_GRANTED }
            .map {
                AppItem(
                    name = it.loadLabel(pm).toString(),
                    packageName = it.packageName,
                    isExcluded = savedExcluded.contains(it.packageName)
                )
            }
            .sortedBy { it.name.lowercase() }

        val recyclerView = findViewById<RecyclerView>(R.id.recyclerApps)
        recyclerView.layoutManager = LinearLayoutManager(this)
        
        adapter = AppsAdapter(allAppsList) { appItem, isChecked ->
            if (isChecked) savedExcluded.add(appItem.packageName) 
            else savedExcluded.remove(appItem.packageName)
            
            prefs.edit().putStringSet("excluded_apps", savedExcluded).apply()
            Toast.makeText(this, "Перезапустите фильтр для применения", Toast.LENGTH_SHORT).show()
        }
        recyclerView.adapter = adapter

        // Логика поиска
        searchBar.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                val query = s.toString().lowercase()
                val filtered = allAppsList.filter { 
                    it.name.lowercase().contains(query) || it.packageName.lowercase().contains(query) 
                }
                adapter.updateList(filtered)
            }
            override fun afterTextChanged(s: Editable?) {}
        })

        btnStart.setOnClickListener {
            val intent = VpnService.prepare(this)
            if (intent != null) {
                vpnLauncher.launch(intent)
            } else {
                startService(Intent(this, LocalDnsVpnService::class.java))
                Toast.makeText(this, "Фильтр запущен", Toast.LENGTH_SHORT).show()
                updateButtonStates(true)
            }
        }

        btnStop.setOnClickListener {
            startService(Intent(this, LocalDnsVpnService::class.java).apply { action = "STOP" })
            Toast.makeText(this, "Фильтр остановлен", Toast.LENGTH_SHORT).show()
            updateButtonStates(false)
        }
    }

    // Логика цветов кнопок
    private fun updateButtonStates(isRunning: Boolean) {
        if (isRunning) {
            btnStart.isEnabled = false
            btnStart.backgroundTintList = ColorStateList.valueOf(Color.GRAY)
            btnStop.isEnabled = true
            btnStop.backgroundTintList = ColorStateList.valueOf(Color.parseColor("#4CAF50"))
        } else {
            btnStart.isEnabled = true
            btnStart.backgroundTintList = ColorStateList.valueOf(Color.parseColor("#4CAF50"))
            btnStop.isEnabled = false
            btnStop.backgroundTintList = ColorStateList.valueOf(Color.GRAY)
        }
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
