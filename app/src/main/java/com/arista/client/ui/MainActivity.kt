package com.arista.client.ui

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.arista.client.R
import com.arista.client.data.models.Config
import com.arista.client.core.CoreTestService
import com.arista.client.core.CoreVpnService
import com.arista.client.databinding.ActivityMainBinding
import com.arista.client.ui.adapters.ConfigAdapter
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var adapter: ConfigAdapter

    @Inject
    lateinit var viewModel: ConfigViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupRecyclerView()
        setupListeners()
        observeData()

        viewModel.loadConfigs()
    }

    private fun setupRecyclerView() {
        adapter = ConfigAdapter(
            onConnectClick = { config ->
                if (config.isActive) {
                    CoreVpnService.stop(this)
                    viewModel.disconnectConfig(config)
                } else {
                    CoreVpnService.start(this, config.link)
                    viewModel.connectConfig(config)
                }
            },
            onTestClick = { config ->
                CoreTestService.startTest(this, listOf(config))
            },
            onRefreshClick = { viewModel.fetchConfigs() }
        )

        binding.recyclerView.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = this@MainActivity.adapter
        }
    }

    private fun setupListeners() {
        binding.swipeRefresh.setOnRefreshListener {
            viewModel.fetchConfigs()
        }
    }

    private fun observeData() {
        lifecycleScope.launch {
            viewModel.configs.collect { configs ->
                adapter.submitList(configs)
                binding.swipeRefresh.isRefreshing = false
            }
        }

        lifecycleScope.launch {
            viewModel.isLoading.collect { isLoading ->
                binding.progressBar.visibility = if (isLoading) android.view.View.VISIBLE else android.view.View.GONE
            }
        }
    }
}
