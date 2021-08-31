/* USER CODE BEGIN Header */
/**
 ******************************************************************************
  * File Name          : hw_conf.h
  * Description        : Hardware configuration file for the application.
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2019 STMicroelectronics.
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
#ifndef HW_CONF_H
#define HW_CONF_H

/******************************************************************************
 * Semaphores
 * THIS SHALL NO BE CHANGED AS THESE SEMAPHORES ARE USED AS WELL ON THE CM0+
 *****************************************************************************/
/**
*  The CPU2 may be configured to store the Thread persistent data either in internal NVM storage on CPU2 or in
*  SRAM2 buffer provided by the user application. This can be configured with the system command SHCI_C2_Config()
*  When the CPU2 is requested to store persistent data in SRAM2, it can write data in this buffer at any time when needed.
*  In order to read consistent data with the CPU1 from the SRAM2 buffer, the flow should be:
*  + CPU1 takes CFG_HW_THREAD_NVM_SRAM_SEMID semaphore
*  + CPU1 reads all persistent data from SRAM2 (most of the time, the goal is to write these data into an NVM managed by CPU1)
*  + CPU1 releases CFG_HW_THREAD_NVM_SRAM_SEMID semaphore
*  CFG_HW_THREAD_NVM_SRAM_SEMID semaphore makes sure CPU2 does not update the persistent data in SRAM2 at the same time CPU1 is reading them.
*  There is no timing constraint on how long this semaphore can be kept.
*/
#define CFG_HW_THREAD_NVM_SRAM_SEMID                    9

/**
*  The CPU2 may be configured to store the BLE persistent data either in internal NVM storage on CPU2 or in
*  SRAM2 buffer provided by the user application. This can be configured with the system command SHCI_C2_Config()
*  When the CPU2 is requested to store persistent data in SRAM2, it can write data in this buffer at any time when needed.
*  In order to read consistent data with the CPU1 from the SRAM2 buffer, the flow should be:
*  + CPU1 takes CFG_HW_BLE_NVM_SRAM_SEMID semaphore
*  + CPU1 reads all persistent data from SRAM2 (most of the time, the goal is to write these data into an NVM managed by CPU1)
*  + CPU1 releases CFG_HW_BLE_NVM_SRAM_SEMID semaphore
*  CFG_HW_BLE_NVM_SRAM_SEMID semaphore makes sure CPU2 does not update the persistent data in SRAM2 at the same time CPU1 is reading them.
*  There is no timing constraint on how long this semaphore can be kept.
*/
#define CFG_HW_BLE_NVM_SRAM_SEMID                    8

/**
*  Index of the semaphore used by CPU2 to prevent the CPU1 to either write or erase data in flash
*  The CPU1 shall not either write or erase in flash when this semaphore is taken by the CPU2
*  When the CPU1 needs to either write or erase in flash, it shall first get the semaphore and release it just
*  after writing a raw (64bits data) or erasing one sector.
*  On v1.4.0 and older CPU2 wireless firmware, this semaphore is unused and CPU2 is using PES bit.
*  By default, CPU2 is using the PES bit to protect its timing. The CPU1 may request the CPU2 to use the semaphore
*  instead of the PES bit by sending the system command SHCI_C2_SetFlashActivityControl()
*/
#define CFG_HW_BLOCK_FLASH_REQ_BY_CPU2_SEMID                    7

/**
*  Index of the semaphore used by CPU1 to prevent the CPU2 to either write or erase data in flash
*  In order to protect its timing, the CPU1 may get this semaphore to prevent the  CPU2 to either
*  write or erase in flash (as this will stall both CPUs)
*  The PES bit shall not be used as this may stall the CPU2 in some cases.
*/
#define CFG_HW_BLOCK_FLASH_REQ_BY_CPU1_SEMID                    6

/**
*  Index of the semaphore used to manage the CLK48 clock configuration
*  When the USB is required, this semaphore shall be taken before configuring te CLK48 for USB
*  and should be released after the application switch OFF the clock when the USB is not used anymore
*  When using the RNG, it is good enough to use CFG_HW_RNG_SEMID to control CLK48.
*  More details in AN5289
*/
#define CFG_HW_CLK48_CONFIG_SEMID                               5

/* Index of the semaphore used to manage the entry Stop Mode procedure */
#define CFG_HW_ENTRY_STOP_MODE_SEMID                            4

/* Index of the semaphore used to access the RCC */
#define CFG_HW_RCC_SEMID                                        3

/* Index of the semaphore used to access the FLASH */
#define CFG_HW_FLASH_SEMID                                      2

/* Index of the semaphore used to access the PKA */
#define CFG_HW_PKA_SEMID                                        1

/* Index of the semaphore used to access the RNG */
#define CFG_HW_RNG_SEMID                                        0

/******************************************************************************
 * HW UART
 *****************************************************************************/
#if (CFG_LPM_SUPPORTED == 0)
#define CFG_HW_LPUART1_ENABLED           1
#define CFG_HW_LPUART1_DMA_TX_SUPPORTED  1
#define CFG_HW_USART1_ENABLED           1
#define CFG_HW_USART1_DMA_TX_SUPPORTED  1
   
#else
#define CFG_HW_LPUART1_ENABLED           0
#define CFG_HW_LPUART1_DMA_TX_SUPPORTED  0
#define CFG_HW_USART1_ENABLED           0
#define CFG_HW_USART1_DMA_TX_SUPPORTED  0  
#endif
/******************************************************************************
 * External PA
 *****************************************************************************/

#if (CFG_LPM_SUPPORTED == 0)
#define CFG_HW_EXTPA_ENABLED           1
#else
#define CFG_HW_EXTPA_ENABLED           0
#endif

#endif /*HW_CONF_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
