package com.example.dnsfilter

import android.app.Activity
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.VpnService
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
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

    private val vpnLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startService(Intent(this, LocalDnsVpnService::class.java))
            Toast.makeText(this, "Фильтр запущен", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val prefs = getSharedPreferences("dns_prefs", MODE_PRIVATE)
        val savedExcluded = prefs.getStringSet("excluded_apps", emptySet())?.toMutableSet() ?: mutableSetOf()

        val pm = packageManager
        val appsList = pm.getInstalledApplications(0)
            .filter { (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 }
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
        recyclerView.adapter = AppsAdapter(appsList) { appItem, isChecked ->
            if (isChecked) {
                savedExcluded.add(appItem.packageName)
            } else {
                savedExcluded.remove(appItem.packageName)
            }
            prefs.edit().putStringSet("excluded_apps", savedExcluded).apply()
            Toast.makeText(this, "Перезапустите фильтр для применения", Toast.LENGTH_SHORT).show()
        }

        findViewById<Button>(R.id.btnStart).setOnClickListener {
            val intent = VpnService.prepare(this)
            if (intent != null) {
                vpnLauncher.launch(intent)
            } else {
                startService(Intent(this, LocalDnsVpnService::class.java))
                Toast.makeText(this, "Фильтр запущен", Toast.LENGTH_SHORT).show()
            }
        }

        findViewById<Button>(R.id.btnStop).setOnClickListener {
            val stopIntent = Intent(this, LocalDnsVpnService::class.java).apply {
                action = "STOP"
            }
            startService(stopIntent)
            Toast.makeText(this, "Фильтр остановлен", Toast.LENGTH_SHORT).show()
        }
    }
}

class AppsAdapter(
    private val items: List<AppItem>,
    private val onToggle: (AppItem, Boolean) -> Unit
) : RecyclerView.Adapter<AppsAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val checkBox: CheckBox = view as CheckBox
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
