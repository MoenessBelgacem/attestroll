#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_app_desc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "fleet_agent";

void app_main(void)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    const esp_app_desc_t *desc = esp_app_get_description();
    esp_ota_img_states_t state;

    ESP_LOGI(TAG, "version=%s slot=%s", desc->version, running->label);

    if (esp_ota_get_state_partition(running, &state) == ESP_OK) {
        ESP_LOGI(TAG, "ota_state=%d (pending_verify=%d)", (int)state, (int)ESP_OTA_IMG_PENDING_VERIFY);
        if (state == ESP_OTA_IMG_PENDING_VERIFY) {
            /* A real self-test goes here (sensors, network, ...). */
            ESP_LOGI(TAG, "self-test OK -> confirming this version");
            esp_ota_mark_app_valid_cancel_rollback();
        }
    }
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(5000));
        ESP_LOGI(TAG, "alive, version=%s", desc->version);
    }
}
