#include <nl_ota_helper.h>

#ifdef NL_DEBUG_PRINT
#define LOG_DEBUG(fmt, ...) printf("%s():%d: " fmt, __func__, __LINE__,  ## __VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...)
#endif // NL_DEBUG_PRINT

#ifndef NL_DISABLE_PRINTS
#define LOG_ERROR(fmt, ...) fprintf(stderr, "%s(%d):" fmt, __func__, __LINE__, ## __VA_ARGS__)
#define LOG_INFO(fmt, ...) printf("%s():%d: " fmt, __func__, __LINE__,  ## __VA_ARGS__)
#else
#define LOG_ERROR(fmt, ...)
#define LOG_INFO(fmt, ...)
#endif // NL_DISABLE_PRINTS

#ifdef NL_JSON
int ota_update_needed_request_serialize(struct ota_update_needed_request* in_obj, char **packet, int *packet_size)
{
    cJSON *root = cJSON_CreateObject();
    if (root == NULL)
    {
        LOG_ERROR("cannot create root cJSON for ota_update_needed_request request\n");
        return -EIO;
    }
    cJSON_AddItemToObject(root, "chipSerial", cJSON_CreateString(in_obj->chip_id));
    cJSON_AddItemToObject(root, "currentFirmwareId", cJSON_CreateNumber(in_obj->fw_version_in_use));
    cJSON_AddItemToObject(root, "deviceSerial", cJSON_CreateString(in_obj->device_siriel));

    *packet = cJSON_PrintUnformatted(root);

    cJSON_Delete(root);

    return 0;
}

int ota_update_needed_request_deserialize(struct ota_update_needed_response *out_obj, char *response)
{
    cJSON *root = NULL;
    cJSON *item = NULL;
    memset(out_obj, 0, sizeof(struct ota_update_needed_response));

    root = cJSON_Parse(response);
    if (root == NULL)
    {
        LOG_ERROR(" cannot create root cJSON for ServerCommandDeserialize\n");
        return -ENOMEM;
    }

    item = cJSON_GetObjectItem(root, "firmwareLocation");
    if (item != NULL)
    {
        out_obj->new_fw_url = (char*) malloc(strlen(item->valuestring) + 1);
        if (out_obj->new_fw_url == NULL)
        {
            LOG_ERROR("No memory");
            return -ENOMEM;
        }
        memset(out_obj->new_fw_url, 0 , strlen(item->valuestring) + 1);
        memcpy(out_obj->new_fw_url, item->valuestring, strlen(item->valuestring));
        LOG_DEBUG("out_obj->new_fw_url: %s\n",out_obj->new_fw_url);
    }

    item = cJSON_GetObjectItem(root, "version");
    if (item != NULL)
    {
        out_obj->new_fw_version = (char*) malloc(strlen(item->valuestring) + 1);
        if (out_obj->new_fw_version == NULL)
        {
            LOG_ERROR("No memory\n");
            return -ENOMEM;
        }
        memset(out_obj->new_fw_version, 0 , strlen(item->valuestring) + 1);
        memcpy(out_obj->new_fw_version, item->valuestring, strlen(item->valuestring));
        LOG_DEBUG("out_obj->new_fw_version: %s\n",out_obj->new_fw_version);
    }

    cJSON_Delete(root);

    return 0;
}
#else // NL_JSON
int ota_update_needed_request_serialize(struct ota_update_needed_request *in_obj, char **packet, int *packet_size)
{
    if(!*packet)
    {
        LOG_ERROR("no allocated memory for packet\n");
        return -ENOMEM;
    }
    memset(*packet, 0, sizeof(struct ota_update_needed_request) + 1);
    memcpy(*packet, in_obj, sizeof(struct ota_update_needed_request));
    *packet_size = sizeof(struct ota_update_needed_request);

    return 0;
}

int ota_update_needed_request_deserialize(struct ota_update_needed_response *out_obj, char *response)
{
    int ret = 0;
    int url_size = -1;
    int fw_size = -1;

    url_size = ((struct ota_update_needed_response *)response)->new_fw_url_size;
    if (url_size < 0)
    {
        LOG_ERROR("faild to extract url size\n");
        return -EIO;
    }
    LOG_DEBUG("url_size : %d\n", url_size);

    out_obj->new_fw_url = malloc(url_size + 1);
    if (out_obj->new_fw_url == NULL)
    {
        LOG_ERROR("No memory");
        return -ENOMEM;
    }

    memset(out_obj->new_fw_url, 0, url_size + 1);

    memcpy(out_obj->new_fw_url, &((struct ota_update_needed_response *)response)->new_fw_url, url_size);
    LOG_DEBUG("out_obj->new_fw_url: %s\n",out_obj->new_fw_url);
    fw_size = (int)response[sizeof(out_obj->new_fw_url_size) + url_size];
    if (fw_size < 0)
    {
        LOG_ERROR("faild to extract frimware size\n");
        return -EIO;
    }
    LOG_ERROR("fw_size: %d\n", fw_size);

    out_obj->new_fw_version = (char*) malloc(fw_size + 1);
    if (out_obj->new_fw_version == NULL)
    {
        LOG_ERROR("No memory\n");
        free(out_obj->new_fw_url);
        return  -ENOMEM;
    }

    memset(out_obj->new_fw_version, 0 , fw_size + 1);
    memcpy(out_obj->new_fw_version, &response[sizeof(out_obj->new_fw_url_size) + url_size + sizeof(out_obj->new_fw_version_size)], fw_size);
    LOG_DEBUG("out_obj->new_fw_version: %s\n", out_obj->new_fw_version);

    return ret;
}
#endif //NL_JSON
