/* USER CODE BEGIN Header */
/**
 ******************************************************************************
  * File Name          : lowpower_app.h
  * Description        : Header for BLE LLD application.
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2021 STMicroelectronics.
  * All rights reserved.</center></h2>
  *
  * This software component is licensed by ST under Ultimate Liberty license
  * SLA0044, the "License"; You may not use this file except in compliance with
  * the License. You may obtain a copy of the License at:
  *                             www.st.com/SLA0044
  *
  ******************************************************************************
 */
/* USER CODE END Header */
/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef LOWPOWER_APP_H
#define LOWPOWER_APP_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/

/* Private includes ----------------------------------------------------------*/

/* Exported types ------------------------------------------------------------*/

/* Exported constants --------------------------------------------------------*/

/* External variables --------------------------------------------------------*/

/* Exported macros ------------------------------------------------------------*/

/* Exported functions ------------------------------------------------------- */
void LOWPOWER_APP_Init(void);
void Appli_TS_Callback(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
