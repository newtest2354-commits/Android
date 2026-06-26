package com.arista.client.ui.adapters

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.arista.client.R
import com.arista.client.data.models.Config
import com.arista.client.databinding.ItemConfigBinding

class ConfigAdapter(
    private val onConnectClick: (Config) -> Unit,
    private val onTestClick: (Config) -> Unit,
    private val onRefreshClick: () -> Unit
) : RecyclerView.Adapter<ConfigAdapter.ConfigViewHolder>() {

    private var items: List<Config> = emptyList()

    fun submitList(list: List<Config>) {
        items = list
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ConfigViewHolder {
        val binding = ItemConfigBinding.inflate(
            LayoutInflater.from(parent.context), parent, false
        )
        return ConfigViewHolder(binding)
    }

    override fun onBindViewHolder(holder: ConfigViewHolder, position: Int) {
        holder.bind(items[position])
    }

    override fun getItemCount(): Int = items.size

    inner class ConfigViewHolder(
        private val binding: ItemConfigBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(config: Config) {
            binding.apply {
                tvRemark.text = config.remark.ifEmpty { config.protocol }
                tvProtocol.text = config.protocol.uppercase()
                tvServer.text = "${config.ip}:${config.port}"
                tvPing.text = if (config.ping > 0) "${config.ping}ms" else "⏳"

                btnConnect.text = if (config.isActive) "قطع" else "اتصال"
                btnConnect.isSelected = config.isActive

                btnConnect.setOnClickListener { onConnectClick(config) }
                btnTest.setOnClickListener { onTestClick(config) }
            }
        }
    }
}
