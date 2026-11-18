package com.example.dnsfilter

import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity

class RulesActivity : AppCompatActivity() {

    private lateinit var etDomain: EditText
    private lateinit var listAdapter: ArrayAdapter<String>
    private var rows: List<Pair<String, Boolean>> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_rules)
        title = "Мои правила"

        RuleStore.load(this)

        etDomain = findViewById(R.id.etDomain)
        val btnBlock = findViewById<Button>(R.id.btnAddBlock)
        val btnAllow = findViewById<Button>(R.id.btnAddAllow)
        val list = findViewById<ListView>(R.id.listRules)
        val tvEmpty = findViewById<TextView>(R.id.tvEmpty)

        listAdapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, mutableListOf<String>())
        list.adapter = listAdapter
        list.emptyView = tvEmpty

        btnBlock.setOnClickListener { addRule(block = true) }
        btnAllow.setOnClickListener { addRule(block = false) }

        list.setOnItemClickListener { _, _, position, _ ->
            confirmRemove(rows[position].first)
        }

        refresh()
    }

    private fun addRule(block: Boolean) {
        val domain = RuleStore.normalize(etDomain.text.toString())
        if (domain == null) {
            Toast.makeText(this, "Введите домен вида example.com", Toast.LENGTH_SHORT).show()
            return
        }
        if (block) {
            if (!RuleStore.addBlocked(this, domain)) {
                Toast.makeText(
                    this,
                    "$domain защищён: его блокировка сломает почту, карты или поиск",
                    Toast.LENGTH_LONG
                ).show()
                return
            }
        } else {
            RuleStore.addAllowed(this, domain)
        }
        etDomain.text.clear()
        Toast.makeText(this, "Готово. Перезапустите браузер", Toast.LENGTH_SHORT).show()
        refresh()
    }

    private fun confirmRemove(domain: String) {
        AlertDialog.Builder(this)
            .setTitle("Удалить правило?")
            .setMessage(domain)
            .setPositiveButton("Удалить") { _, _ ->
                RuleStore.remove(this, domain)
                refresh()
            }
            .setNegativeButton("Отмена", null)
            .show()
    }

    private fun refresh() {
        rows = RuleStore.entries()
        listAdapter.clear()
        listAdapter.addAll(rows.map { (domain, isBlock) ->
            if (isBlock) "🚫 $domain — моя блокировка" else "✅ $domain — разрешён"
        })
        listAdapter.notifyDataSetChanged()
    }
}
