#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "software_imp.h"
#include "crypto/sha2.h"
#include "crypto/hmac_sha2.h"
//#include <time/jsom_time.h>
//#include <sal/jsom_sal.h>
//#include <flashdev/jsom_flashdev.h>
//#include <platform_opts.h>
#include <nanolock.h>
//#include <screen_handler.h>
//#include "stm32wbxx_hal.h"
//#include "stm32wbxx_nucleo.h"
#include <inc/main.h>
#include <software_imp_st.h>
#include <nl_library/inc/nl_serial_helper.h>


//uint8_t aTxEndMessage[] = "\n\r we are in write\n\r";
//uint8_t aTxStartMessage[] = "\n\r ****UART-Hyperterminal communication based on IT ****\n\r Enter 10 characters using keyboard :\n\r";
uint32_t PageToAddress(uint32_t Page);
int nanolock_is_flash_locked(unsigned long long addr, unsigned long long len);


extern UART_HandleTypeDef huart1;
extern char stringtoprint[20];

uint8_t myMSG[] = "\n\r myMSG \n\r";
uint8_t	myMSG1[]="\n\r myMSG1 \n\r";
uint8_t	myMSG2[]="\n\r myMSG2 \n\r";
uint8_t	myMSG3[]="\n\r myMSG3 \n\r";
uint8_t	myMSG4[]="\n\r myMSG4 \n\r";
uint8_t	myMSG5[]="\n\r myMSG5 \n\r";

uint64_t collectData1=0x0;
uint64_t collectData2=0x0;
uint64_t collectData3=0x0;
uint64_t collectData4=0x0;
uint64_t collectData5=0x0;
uint64_t collectData6=0x0;
uint64_t collectData7=0x0;
uint64_t collectData8=0x0;


uint32_t nAddress = 0;
uint32_t SECTORError;
static FLASH_EraseInitTypeDef EraseInitStruct;

#define DATA_64                 ((uint64_t)0x1234567812345678)

#define WRITE_MIN_SIZE           1


#define pr_emerg(...) printf(__VA_ARGS__)
#define pr_warn(...) printf(__VA_ARGS__)
#define pr_info(...) printf(__VA_ARGS__)
#define pr_debug(...) printf(__VA_ARGS__)
//#define vmalloc jsom_mem_alloc
//#define vfree jsom_mem_free

#define PAGE_SIZE 4096
// #define prn_debug printf

#define JSOM_SUCCESS 0 
#define JSOM_ERR_FAIL 7 

uint32_t data322 = 0;
uint32_t Tosend[1];
char     TosendSTRING[20];
char data_out[12288] ={"Hello FLASH from ControllerTech ThiS iS a teSt to See how many wordS can we work with"};

// Access to logic vars
extern struct nl_nvm_struct nl_nvm;
extern struct nl_vm_struct nl_vm;


int flash_read_data(unsigned int mtd_num , uint32_t StartPageAddress, uint32_t *RxBuf, uint32_t numberofwords)
{
  int i=0;
	int actualNumberOfWords;


	actualNumberOfWords=numberofwords/4;
  //if (nanolock_is_flash_read_locked(StartPageAddress, numberofwords))
  //  return JSOM_ERR_FAIL;

  while (1)
  {
		*(RxBuf + i) = *(__IO uint32_t *)(StartPageAddress);
	 	StartPageAddress += 4;
		i++;
		if (!(actualNumberOfWords--)) break;
  }

 return JSOM_SUCCESS;
}

uint32_t min(uint32_t a, uint32_t b)
{
	return a < b ? a : b;
}

uint32_t max(uint32_t a, uint32_t b)
{
	return a > b ? a : b;
}


static uint32_t GetPage(uint32_t Addr)
{
  return (Addr - FLASH_BASE) / FLASH_PAGE_SIZE;;
}

              //5  7
#define roundup(x, y) (					\
{							\
	const typeof(y) __y = y;			\
	(((x) + (__y - 1)) / __y) * __y;		\
}							\
)

static int memcmpb(void *a, int c, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		if (c != ((unsigned char *)a)[i])
			return 1;
	}
	return 0;
}


int mtd_simple_read(unsigned int mtd_num, unsigned int offset, char *data, uint32_t data_size)
{
	return flash_read_data(mtd_num, nanolock_absolute_address(mtd_num, offset)  + 0x08000000 , data, data_size) == JSOM_SUCCESS ? 0 : -EIO;
}

 int mtd_simple_erase(unsigned int mtd_num, unsigned int offset, uint32_t len)
 {
 	int ret = 0;
 #ifndef NL_QUICKNDIRTY_FLASHOPS
 	unsigned int read_off;
 	int erase_required = 0;
 	char *buf = NULL;
 #endif // NL_QUICKNDIRTY_FLASHOPS


	//MX_USART1_UART_Init(&huart1);

	uint32_t StartPageAddress = nanolock_absolute_address(mtd_num , offset) + 0x08000000;
	uint32_t numberofwords = len;


 	// Sanity check for the erase size
	if (len % FLASH_PAGE_SIZE != 0) {
			//BSP_LED_On(LED1);

 		pr_emerg("Nanolock: mtd erase bad params\n");
		ret = -EINVAL;
		goto out;
	}

 #ifndef NL_QUICKNDIRTY_FLASHOPS
 	// Make sure to erase only if needed
 	buf = malloc(FLASH_PAGE_SIZE);
 	if (buf == NULL) {
 		ret = -ENOMEM;
 		goto out;
 	}
  

 	for (read_off = 0; read_off < len; read_off += FLASH_PAGE_SIZE) {
 		//////////////////////0 temp //////////////////////////////
  	ret = mtd_simple_read(mtd_num , offset + read_off, buf , min(FLASH_PAGE_SIZE , len - read_off) );
 		if (ret < 0)
 			goto out_free;
 		if (memcmpb(buf, 0xff, FLASH_PAGE_SIZE) != 0) {
 			erase_required = 1;
 			break;
 		}
 	}



 	if (!erase_required) {
 		prn_debug("Nanolock: block at address %u already erased, skipping\n", offset);
 		goto out_free;
 	}
 #endif // NL_QUICKNDIRTY_FLASHOPS

HAL_FLASH_Unlock();

__HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_OPTVERR);

uint32_t FirstPage = GetPage(StartPageAddress);
uint32_t NbOfPages = GetPage(StartPageAddress + numberofwords)- FirstPage + 1;

	//Fill EraseInit structure
EraseInitStruct.TypeErase   = FLASH_TYPEERASE_PAGES;
EraseInitStruct.Page        = FirstPage;
EraseInitStruct.NbPages     = NbOfPages;



   
/* Note: If an erase operation in Flash memory also concerns data in the data or instruction cache,
	  you have to make sure that these data are rewritten before they are accessed during code
	  execution. If this cannot be done safely, it is recommended to flush the caches by setting the
	  DCRST and ICRST bits in the FLASH_CR register. */
if (HAL_FLASHEx_Erase(&EraseInitStruct, &SECTORError) != HAL_OK)
{  

//	BSP_LED_Toggle(LED3);

/*********************************/
//  if(HAL_UART_Transmit_IT(&huart1, (uint8_t*)myMSG3, sizeof(myMSG))!= HAL_OK)
// 	{
  	/* Transfer error in transmission process */
//  	Error_Handler();
//  }
		/********************************/
	  ret = HAL_FLASH_GetError ();
	  pr_warn("Nanolock: Failed to erase mtd %d(size:%lu) offset: %u len: %u err: %d\n", mtd_num,FLASH_PAGE_SIZE , offset, len, ret);
	  return -EIO; 
}

 	prn_debug("Nanolock: erase mtd %d offset: %u len: %u\n", mtd_num, offset, len);

 #ifndef NL_QUICKNDIRTY_FLASHOPS
 out_free:
 	free(buf);
 #endif // NL_QUICKNDIRTY_FLASHOPS

 out:
	return ret;
}




int mtd_simple_write(unsigned int mtd_num, unsigned int offset, char *data, uint32_t data_size)
{
	int ret;
#ifndef NL_QUICKNDIRTY_FLASHOPS
	char *buf;
#endif // NL_QUICKNDIRTY_FLASHOPS

	uint32_t StartPageAddress = nanolock_absolute_address(mtd_num, offset) + 0x08000000 ; 
	
	uint16_t numberofwords = data_size;
	int sofar=0;

	// Sanity check for the write size
	if (numberofwords % WRITE_MIN_SIZE != 0) {
	//		BSP_LED_On(LED1);
		/*********************************/
 // 		 if(HAL_UART_Transmit_IT(&huart1, (uint8_t*)myMSG3, sizeof(myMSG))!= HAL_OK)
 // 		 {
  		   /* Transfer error in transmission process */
 //  			  Error_Handler();
 //  		 }
		/********************************/

		pr_emerg("Nanolock: mtd write bad params\n");
		ret = -EINVAL;
		goto out;
	}

	 /* Unlock the Flash to enable the flash control register access *************/
	  HAL_FLASH_Unlock();

  __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_OPTVERR);

	/* Erase the user Flash area */

	/* Get the number of sector to erase from 1st sector */

//	uint32_t FirstPage = GetPage(StartPageAddress);
//	uint32_t NbOfPages = GetPage(StartPageAddress + numberofwords)- FirstPage + 1;

	//Fill EraseInit structure
//	EraseInitStruct.TypeErase   = FLASH_TYPEERASE_PAGES;
//  EraseInitStruct.Page        = FirstPage;
//  EraseInitStruct.NbPages     = NbOfPages;

//	if (HAL_FLASHEx_Erase(&EraseInitStruct, &SECTORError) != HAL_OK)
//	{
	/*********************************/
//  	if(HAL_UART_Transmit_IT(&huart1, (uint8_t*)myMSG2, sizeof(myMSG))!= HAL_OK)
//  	{
//  			Error_Handler();
//  	}

//	  	  ret = HAL_FLASH_GetError ();
//	  	 pr_warn("Nanolock: Failed to erase before write %ld\n", ret);
//		return -EIO; 
//	}

	/* Program the user Flash area word by word*/

	   while (sofar<numberofwords)
	   {
	    	// BSP_LED_On(LED1);

			 /*collectData= ((uint64_t)data[sofar+1]) << 32;
			   collectData= collectData | (uint64_t)data[sofar];*/

	   	 collectData1 = ((uint64_t)data[sofar+7]) << 56;
			 collectData2 = collectData1 | (uint64_t)data[sofar+6] << 48;
			 collectData3 = collectData2 | (uint64_t)data[sofar+5] << 40;
			 collectData4 = collectData3 | (uint64_t)data[sofar+4] << 32;
			 collectData5 =	collectData4 | (uint64_t)data[sofar+3] << 24;
			 collectData6 = collectData5 | (uint64_t)data[sofar+2] << 16;
			 collectData7 = collectData6 | (uint64_t)data[sofar+1] << 8;
			 collectData8 = collectData7 | (uint64_t)data[sofar+0] ; 

	     if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, StartPageAddress ,(uint64_t)collectData8) == HAL_OK)
	     {
	    	 StartPageAddress += 8; 
	    	 sofar=sofar+8;
	     }
	    else
	     {
	       /* Error occurred while writing data in Flash memory*/
	       pr_warn("Nanolock: Failed to write to mtd %d\n", ret);
		   ret = -EIO;
		   goto out;
	     }
	   }

	prn_debug("Nanolock: write mtd %d offset: %u len: %u\n", mtd_num, offset, numberofwords);


#ifndef NL_QUICKNDIRTY_FLASHOPS
	// Check that the flash realy written the data
	buf = NULL;
	buf = (char *)malloc(numberofwords);

	if (buf == NULL) {
		//BSP_LED_On(LED2);

		pr_emerg("Nanolock: Not enough memory!\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = mtd_simple_read(mtd_num, offset, buf, numberofwords);
	
		
	if (ret < 0) {
		pr_warn("Nanolock: Failed to read from mtd %d\n", ret);
//	  BSP_LED_On(2);

		if (ret >= 0)
		{
			ret = -EIO;
		}
		goto out_free;
	}

	if ( memcmp((char *)buf, (char *)data,numberofwords) != 0 ) {
		pr_warn("Nanolock: mtd write and read doesn't match, part: %d, addr: 0x%x\n", mtd_num, offset);
	//  BSP_LED_On(2);
		ret = -EIO;
		goto out_free;
	}
	else {  /*BSP_LED_On(LED1);*/ }


HAL_FLASH_Unlock();
	

out_free:
	free(buf);
#endif // NL_QUICKNDIRTY_FLASHOPS
out:
	return ret;
}

 int CalculateSHA(char *data, uint32_t data_size, char *result)
 {
 	sha256((unsigned char*)data, data_size, (unsigned char*)result);
 	return 0;
 }
 int CalculateHMAC(char *data, uint32_t data_size, char *key, uint32_t key_size, char *result)
 {
	hmac_sha256((unsigned char*)key, key_size, (unsigned char*)data, data_size, (unsigned char*)result, NL_SIGNATURE_LEN);
 	return 0;
 }

 int CalculateUserSHA(char *data, uint32_t data_size, char *result)
 {
 	return CalculateSHA(data, data_size, result);
 }

 int calculate_image_sha(char *data, uint32_t data_size, char *result)
 {
 #ifndef NL_UPDATE_PASS_FILE
 	return CalculateUserSHA(data, data_size, result);
 #else // NL_UPDATE_PASS_FILE
 	return CalculateFileSHA(NL_SWAPFILE_PATH, data_size, result);
 #endif // NL_UPDATE_PASS_FILE
 }

 int calculate_partition_SHA(int partition_index, uint32_t data_size, char *result)
 {
 	int ret = 0;
	sha256_ctx ctx;
	char *buffer = NULL;
	uint32_t offset = 0;
	unsigned int chunk_size;

	if (partition_index < 0 || partition_index > nl_nvm.register_config.partitionAmount || result == NULL)
	{
		return -EINVAL;
	}

	// Init sha
	sha256_init(&ctx);

	buffer = malloc(NL_BUFFER_SIZE /*, GFP_KERNEL*/);
	if (!buffer) {
		ret = -ENOMEM;
		goto out;
	}

	while (offset < data_size) {
		chunk_size = min((uint32_t)NL_BUFFER_SIZE, data_size - offset);
		ret = mtd_simple_read(partition_index, offset, buffer, chunk_size);
		if (ret < 0)
		{
			pr_warn("Nanolock: Failed to read from blkdev. error: %d", ret);
			goto err_free_buffer;
		}
		sha256_update(&ctx, buffer, chunk_size);
		offset += chunk_size;
	}

	sha256_final(&ctx, result);

err_free_buffer:
	free(buffer);
out:
 	return ret;
 }

 int nanolock_install_ota_v2_internal(struct nl_nvm_struct *nvm, IOCTL_InstallOTA *obj, char *image_data, char *signature)
 {
 	return 0;
 }

 long nanolock_ioctl_v2(unsigned int cmd, unsigned long arg, struct nl_nvm_struct *nvm)
 {
 	return -ENOTTY;
 }

 void spin_lock(spinlock_t *lock)
 {

 }

 void spin_unlock(spinlock_t *lock)
 {

 }

 void spin_lock_init(spinlock_t *lock)
 {

 }

 void mutex_lock(struct mutex *lock)
 {

 }

 void mutex_unlock(struct mutex *lock)
 {

 }


 unsigned int system_get_current_ticks(void)
 {

 	// MX_USART1_UART_Init(&huart1);
		

 	static unsigned int uptime_ticks = 0;
 	static unsigned int last_ticks = 0;
 	/*jsom_timestamp_t ticks;
  	jsom_get_uptime(&ticks);
  	printf("Current jsom_get_uptime: %lu, %u, %u\n", ticks.sec, ticks.nsec);*/

  	uint32_t ticks = HAL_GetTick();
 	/*printf("Current jsom_getms: %u, sec: %u\n", ticks, ticks / 1000);*/
  	ticks = ticks / 1000;

 	// Handle wrap around
 	if (ticks < last_ticks)
 		uptime_ticks += ticks + (0xffffffff / 1000 - last_ticks);
 	else
 		uptime_ticks += ticks - last_ticks;

 	last_ticks = ticks;

	return uptime_ticks;
 }

 #ifdef NL_CONFIG_RAW_ALGO
 int nanolock_save_register_config_blkdev(struct nl_nvm_struct *nvm)
{
 	int ret = 0;
 	char *buf;
 	unsigned int buf_len;

 #if NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 	unsigned int erase_size = roundup(roundup(sizeof(nvm->register_config), NL_WRITE_BLOCK_SIZE)
 		+ roundup(NL_OTPM_LEN, NL_WRITE_BLOCK_SIZE), NL_ERASE_BLOCK_SIZE);
 #endif // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR


 // temp should be active - efis
 //	if (nvm->OTPMData == NULL)
 //		{ 		
 //		BSP_LED_On(LED3);
//		return -EINVAL;
// 	}

 	buf_len = max((unsigned int)sizeof(nvm->register_config), (unsigned int)NL_OTPM_LEN);
 #if NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 	buf_len = roundup(buf_len, (unsigned int)NL_WRITE_BLOCK_SIZE);
 #endif // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR

// 	BSP_LED_On(1);

 	buf = (char *)malloc(buf_len);
 	/////////////1024
 	if (buf == NULL)
 	{
 		
 		return -ENOMEM;
 	}

 	memset(buf, 0, buf_len);

 	do {
 		if (nl_vm.config_actual_offset >= NL_CONFIG_OFFSET + NL_ERASE_BLOCK_AMOUNT * NL_ERASE_BLOCK_SIZE) {
 			pr_emerg("Nanolock: All nvm blocks are bad, failed to save chip config\n");
 			ret = -EFAULT;
 	 			goto out;
 		}

 #if NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 		// mtd requires erase before write
 		ret = mtd_simple_erase(NL_CONFIG_PARTITION, nl_vm.config_actual_offset, erase_size);
 		if (ret < 0) {
 			nl_vm.config_actual_offset += erase_size;
 			continue;
 		}
 #endif // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR

 
 		// Saving the config in buf so the config will always have meaningful data
 		obscure_buffer((char*)&nvm->register_config, sizeof(nvm->register_config), buf);

 #if NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 		ret = mtd_simple_write(NL_CONFIG_PARTITION, nl_vm.config_actual_offset, buf,roundup(sizeof(nvm->register_config), NL_WRITE_BLOCK_SIZE));
 #else // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 		ret = blkdev_simple_write(NL_CONFIG_DEVICE, NL_CONFIG_PARTITION, nl_vm.config_actual_offset, buf, sizeof(nvm->register_config), true);
 #endif // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 		if (ret < 0) {
 			nl_vm.config_actual_offset += erase_size;
 		//	BSP_LED_On(1);
 			continue;
 		}

		memset(buf, 0, buf_len);
		obscure_buffer(nvm->OTPMData, NL_OTPM_LEN, buf);
#if NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
		ret = mtd_simple_write(NL_CONFIG_PARTITION, nl_vm.config_actual_offset + roundup(sizeof(nvm->register_config), NL_WRITE_BLOCK_SIZE),
			buf,  roundup(NL_OTPM_LEN, NL_WRITE_BLOCK_SIZE));
#else // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
		ret = blkdev_simple_write(NL_CONFIG_DEVICE, NL_CONFIG_PARTITION,
			nl_vm.config_actual_offset + roundup(sizeof(nvm->register_config), SECTOR_SIZE), buf, NL_OTPM_LEN, true);
#endif // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
		if (ret < 0) {
			nl_vm.config_actual_offset += erase_size;
			//BSP_LED_On(2);

			continue;
		}
 	} while (ret < 0);

  
 out:
 	free(buf);
// 	BSP_LED_On(2);
 	return ret;
 }

 int algo_next_block(struct nl_nvm_struct *nvm)
 {
 	nl_vm.config_next_block++;
 	nl_vm.config_next_copy = 0;

 	// TODO: NL_ERASE_BLOCK_AMOUNT is only for testing, need to use the partition size instead
 	if (nl_vm.config_next_block >= NL_ERASE_BLOCK_AMOUNT) {
 		nl_vm.config_next_block = 0;
 	}

 	return 0;
 }

 int algo_next_copy(struct nl_nvm_struct *nvm)
 {
 	nl_vm.config_next_copy++;
 	if (nl_vm.config_next_copy >= NL_ERASE_BLOCK_SIZE / NL_CONFIG_COPY_SIZE) {
 		algo_next_block(nvm);
 }

 	prn_debug("Nanolock: changed to block %d copy %d\n", nl_vm.config_next_block, nl_vm.config_next_copy);

 	return 0;
 }

 unsigned int algo_next_copy_address(struct nl_nvm_struct *nvm)
 {
 	unsigned int offset = nl_vm.config_actual_offset + NL_ERASE_BLOCK_SIZE;
 	offset += nl_vm.config_next_block * NL_ERASE_BLOCK_SIZE + nl_vm.config_next_copy * NL_CONFIG_COPY_SIZE;
 	return offset;
 }

// // As bad blocks are not handled currently, keep going no matter what
 int nanolock_save_config_blkdev(struct nl_nvm_struct *nvm)
 {
 	char *buf;
 	int ret = 0;
 	int ret2 = 0;
 	unsigned int buf_len = PAGE_SIZE;
 	int is_first_copy = false;
 	// The first block is used by the registration config
 	unsigned int offset = 0;

 	// Make sure that the size defined make sense
 	/*BUILD_BUG_ON_MSG(PAGE_SIZE < roundup(sizeof(nvm->config) + sizeof(nvm->event_logs), NL_WRITE_BLOCK_SIZE),
 	 	"The nvm config is bigger than PAGE_SIZE, fix this!");*/

 	buf = malloc(buf_len/*, GFP_KERNEL*/);
 	if (buf == NULL) {
 		pr_emerg("Nanolock: Not enough memory!\n");
 		return -ENOMEM;
 	}



 	memset(buf, 0, buf_len);

 	// Saving the config in buf so the config will always have meaningful data
 	obscure_buffer((char*)&nvm->config, sizeof(nvm->config), buf);

 	do {
 		offset = algo_next_copy_address(nvm);

 		// mtd requires erase before write, we will actually write in next part because of padding issues
 		if (nl_vm.config_next_copy == 0) {
 			is_first_copy = true;
 #if NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 			ret = mtd_simple_erase(NL_CONFIG_PARTITION, offset, NL_ERASE_BLOCK_SIZE);
 #endif // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 		}

 #if NL_CONFIG_DEVICE != MTD_BLOCK_MAJOR
 		// Write config
 		ret = blkdev_simple_write(NL_CONFIG_DEVICE, NL_CONFIG_PARTITION, offset, buf, sizeof(nvm->config), true);
 #endif // NL_CONFIG_DEVICE != MTD_BLOCK_MAJOR
 		// Handle bad block
 		if (ret < 0) {
 			algo_next_copy(nvm);
 			continue;
 		}


///here

 	// Write config and logs for mtd or else just logs
 #if NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 		obscure_buffer((char*)nvm->event_logs, sizeof(nvm->event_logs), &buf[sizeof(nvm->config)]);
// here 2
 		ret = mtd_simple_write(NL_CONFIG_PARTITION, offset,
 			buf, roundup(sizeof(nvm->config) + sizeof(nvm->event_logs), NL_WRITE_BLOCK_SIZE));
 #else // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 		obscure_buffer((char*)nvm->event_logs, sizeof(nvm->event_logs), buf);
 		ret = blkdev_simple_write(NL_CONFIG_DEVICE, NL_CONFIG_PARTITION, offset + roundup(sizeof(nvm->config), SECTOR_SIZE),
 			buf, sizeof(nvm->event_logs), true);
 #endif // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 		if (ret < 0) {
 			algo_next_copy(nvm);
 			continue;
 		}
     		

// 		BSP_LED_On(2);

 	} while (ret < 0);

 	prn_debug("Nanolock: saved to block: %d, copy: %d\n", nl_vm.config_next_block, nl_vm.config_next_copy);
 	

 	// After writing to a new block erase previous block, if we fail, don't report it as have nothing to do with it
 	if (is_first_copy && nl_vm.config_prev_block != nl_vm.config_next_block) {
 		offset = nl_vm.config_actual_offset + NL_ERASE_BLOCK_SIZE;
 		offset += nl_vm.config_prev_block * NL_ERASE_BLOCK_SIZE;
		prn_debug("Nanolock: erasing previous block: %d, offset: %u\n", nl_vm.config_prev_block, offset);
 #if NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 		ret2 = mtd_simple_erase(NL_CONFIG_PARTITION, offset, NL_ERASE_BLOCK_SIZE);
 #else // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 		ret2 = blkdev_fill(NL_CONFIG_DEVICE, NL_CONFIG_PARTITION, offset, 0xff, NL_ERASE_BLOCK_SIZE, true);
 #endif // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 		if (ret2 < 0)
 			pr_emerg("Nanolock: erasing block failed with: %d\n", ret2);
 	}

 	// Update prev block & copy
 	nl_vm.config_prev_block = nl_vm.config_next_block;
 	nl_vm.config_prev_copy = nl_vm.config_next_copy;

 	// Update indices for next saving offset
 	algo_next_copy(nvm);
 	prn_debug("Nanolock: next save block: %d, copy: %d\n", nl_vm.config_next_block, nl_vm.config_next_copy);



 	free(buf);
 	return ret;
 }

 int nanolock_load_config_copy_blkdev(struct nl_nvm_struct *nvm, unsigned int offset)
 {
 	int ret = 0;

 #if NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 	ret = mtd_simple_read(NL_CONFIG_PARTITION, offset, (char*)&nvm->config, sizeof(nvm->config));
 #else // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 	ret = blkdev_simple_read(NL_CONFIG_DEVICE, NL_CONFIG_PARTITION, offset,
 		(char*)&nvm->config, sizeof(nvm->config));
 #endif // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 	if (ret < 0) {
 		pr_warn("Nanolock: failed to read chip config\n");
 		goto out;
 	}
 	obscure_buffer((char*)&nvm->config, sizeof(nvm->config), (char*)&nvm->config);

 	// Logs
 #if NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 	ret = mtd_simple_read(NL_CONFIG_PARTITION, offset + sizeof(nvm->config),
 		(char*)nvm->event_logs, sizeof(nvm->event_logs));
 #else // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 	ret = blkdev_simple_read(NL_CONFIG_DEVICE, NL_CONFIG_PARTITION, offset + roundup(sizeof(nvm->config), SECTOR_SIZE),
 		(char*)nvm->event_logs, sizeof(nvm->event_logs));
 #endif // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 	if (ret < 0) {
 		pr_warn("Nanolock: failed to read chip logs\n");
 		goto out;
 	}
 	obscure_buffer((char*)nvm->event_logs, sizeof(nvm->event_logs), (char*)nvm->event_logs);

 	//BSP_LED_On(0);
 out:
	return ret;
 }
// to be checked 
 int nanolock_load_config_blkdev(struct nl_nvm_struct *nvm)
 {
 	int ret = 0;
 	unsigned int offset = nl_vm.config_actual_offset + NL_ERASE_BLOCK_SIZE;
 	unsigned int block_index;
 	unsigned int copy_index;
 	unsigned int best_block_index = 0;
 	unsigned int best_copy_index = 0;
 	unsigned int found_good_copy = 0;
 	struct nl_nvm_struct *nvm_copy;
 	char nvm_sign[NL_SIGNATURE_LEN];

 	// Make sure that the size defined make sense
 	/*BUILD_BUG_ON_MSG(NL_ERASE_BLOCK_SIZE < sizeof(struct nl_register_config) + NL_OTPM_LEN,
 		"NL_ERASE_BLOCK_SIZE is too small");

 #if NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 	BUILD_BUG_ON_MSG(NL_CONFIG_COPY_SIZE % NL_WRITE_BLOCK_SIZE != 0,
 		"NL_CONFIG_COPY_SIZE must be a multiple of NL_WRITE_BLOCK_SIZE");
 #endif // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR*/

 	nvm_copy = (struct nl_nvm_struct *)kmalloc(sizeof(struct nl_nvm_struct), GFP_KERNEL);
 	if (nvm_copy == NULL) {
 		pr_emerg("Nanolock: Not enough memory!\n");
 		return -ENOMEM;
 	}

 	// Allocate OTPM
 	if (nvm->OTPMData == NULL)
 	{
 		nvm->OTPMData = kmalloc(NL_OTPM_LEN, GFP_KERNEL);
 		if (nvm->OTPMData == NULL) {
 			pr_emerg("Nanolock: Not enough memory!\n");
 			ret = -ENOMEM;
 			goto out;
 		}
 	}

 	do {
 		if (nl_vm.config_actual_offset >= NL_CONFIG_OFFSET + NL_ERASE_BLOCK_AMOUNT * NL_ERASE_BLOCK_SIZE) {
 			pr_emerg("Nanolock: Chip register config was thrashed\n");
 			nl_vm.module_tainted = true;
 			ret = -EFAULT;
 			goto out;
 		}

 	// Register config
 #if NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 		ret = mtd_simple_read(NL_CONFIG_PARTITION, nl_vm.config_actual_offset,
 			(char*)&nvm->register_config, sizeof(nvm->register_config));
 #else // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 		ret = blkdev_simple_read(NL_CONFIG_DEVICE, NL_CONFIG_PARTITION, nl_vm.config_actual_offset,
 			(char*)&nvm->register_config, sizeof(nvm->register_config));
 #endif // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 		if (ret < 0) {
 			if (ret == -ENXIO || ret == -ENODEV)
 				goto out;
 			pr_warn("Nanolock: failed to read chip config at %u\n", nl_vm.config_actual_offset);
 			nl_vm.config_actual_offset += NL_ERASE_BLOCK_SIZE;
 			//BSP_LED_On(0);
 			continue;
 		}
 		obscure_buffer((char*)&nvm->register_config, sizeof(nvm->register_config), (char*)&nvm->register_config);

 		// Keys
 #if NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 		ret = mtd_simple_read(NL_CONFIG_PARTITION, nl_vm.config_actual_offset + roundup(sizeof(nvm->register_config), NL_WRITE_BLOCK_SIZE),
 			(char*)nvm->OTPMData, NL_OTPM_LEN);
 #else // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 		ret = blkdev_simple_read(NL_CONFIG_DEVICE, NL_CONFIG_PARTITION,
 			nl_vm.config_actual_offset + roundup(sizeof(nvm->register_config), SECTOR_SIZE), (char*)nvm->OTPMData, NL_OTPM_LEN);
 #endif // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 		if (ret < 0) {
 			pr_warn("Nanolock: failed to read chip keys at %u\n", nl_vm.config_actual_offset);
 			nl_vm.config_actual_offset += NL_ERASE_BLOCK_SIZE;
// 			BSP_LED_On(0);
 			continue;
 		}
 		obscure_buffer(nvm->OTPMData, NL_OTPM_LEN, nvm->OTPMData);

		// Check the register config
		memset(nvm_sign, 0, sizeof(nvm_sign));
		ret = recalculate_register_config_sign(nvm, nvm_sign);
		if (ret < 0) {
			pr_emerg("Nanolock: Failed to calculate chip register config signature\n");
			//BSP_LED_On(0);
			goto out;
		}

		if (memcmp(nvm_sign, nvm->register_config.config_sign, sizeof(nvm_sign)) != 0) {
			pr_warn("Nanolock: Chip register config at %u is bad\n", nl_vm.config_actual_offset);
			ret = -EFAULT;
			nl_vm.config_actual_offset += NL_ERASE_BLOCK_SIZE;
	//		BSP_LED_Toggle(0);
			continue;
		}
	} while (ret < 0);

	pr_info("Nanolock: found good chip register config at %u\n", nl_vm.config_actual_offset);

	// Mark the config as verified after successfully reading and verifying the register config
	nl_vm.config_verified = 1;

	// Find best config copy
	offset = nl_vm.config_actual_offset + NL_ERASE_BLOCK_SIZE;

#ifdef NL_CONFIG_READ_LOCK
	// After loading the registration data need to unlock config partition in order to read everything else
	ret = unlock_read(nvm);
	if (ret < 0) {
		pr_emerg("Nanolock: failed to unlock for read\n");
//		BSP_LED_On(0);

		goto out;
	}
#endif // NL_CONFIG_READ_LOCK

	// TODO: NL_ERASE_BLOCK_AMOUNT is only for testing, need to use the partition size instead
	for (block_index = 0; found_good_copy == 0 && block_index < NL_ERASE_BLOCK_AMOUNT; block_index++) {
		for (copy_index = 0; copy_index < NL_ERASE_BLOCK_SIZE / NL_CONFIG_COPY_SIZE; copy_index++) {
			unsigned int current_offset = offset + block_index * NL_ERASE_BLOCK_SIZE + copy_index * NL_CONFIG_COPY_SIZE;

			ret = nanolock_load_config_copy_blkdev(nvm_copy, current_offset);
			if (ret < 0) {
				pr_emerg("Nanolock: failed to load nvm copy\n");
				//BSP_LED_On(0);

				goto out;
			}

			memset(nvm_sign, 0, sizeof(nvm_sign));
			ret = RecalculateNVMSignature(nvm_copy, nvm_sign);
			if (ret < 0) {
				pr_emerg("Nanolock: failed to calculate nvm signature\n");
//				BSP_LED_On(0);
				goto out;
			}

			// Make sure it's for this chip id
			if (memcmp(nvm->register_config.chipId, nvm_copy->config.chipId, sizeof(nvm->register_config.chipId)) != 0) {
				prn_debug("Nanolock: config at addr %d is for other chipid or bad\n", current_offset);
//				BSP_LED_On(0);
				continue;
			}

			//BSP_LED_On(1);

			// Check if found good copy, no need to search in other blocks anymore
			if (memcmp(nvm_sign, nvm_copy->config.config_sign, sizeof(nvm_sign)) == 0) {
				best_block_index = block_index;
				best_copy_index = copy_index;
				found_good_copy = 1;
				pr_info("Nanolock: load chip config found good copy in block:%d,copy:%d\n", block_index, copy_index);
//				BSP_LED_On(1);
			} else {
				prn_debug("Nanolock: config at addr %d(block:%d,copy:%d) has bad signature\n", current_offset, block_index, copy_index);
				//BSP_LED_On(0);
			}
		}
	}

	// If failed to find good copy, it means we only have register config to rely on, so erase config
	if (found_good_copy == 0) {
		memset(&nvm->config, 0, sizeof(nvm->config));
		memset(&nvm->event_logs, 0, sizeof(nvm->event_logs));
		nanolock_config_default(nvm);
		RecalculateNVMSignature(nvm, nvm_sign);
		ret = 0;
		pr_emerg("Nanolock: Failed to find good config copy\n");
		goto out;
	}

	// Load best config
	offset += best_block_index * NL_ERASE_BLOCK_SIZE + best_copy_index * NL_CONFIG_COPY_SIZE;
	ret = nanolock_load_config_copy_blkdev(nvm, offset);
	if (ret < 0)
		goto out;
	nl_vm.config_next_block = best_block_index;
	nl_vm.config_next_copy = best_copy_index;
	pr_info("Nanolock: load best block: %d, best copy: %d\n", nl_vm.config_next_block, nl_vm.config_next_copy);

#ifdef NL_CONFIG_READ_LOCK
	// After loading the registration data need to lock config partition
	ret = lock_read(nvm);
	if (ret < 0) {
		pr_emerg("Nanolock: failed to lock for read\n");
		goto out;
	}
#endif // NL_CONFIG_READ_LOCK

	// Update prev block & copy
	nl_vm.config_prev_block = nl_vm.config_next_block;
	nl_vm.config_prev_copy = nl_vm.config_next_copy;

	// Update indices for next saving offset
	algo_next_copy(nvm);
	pr_info("Nanolock: next block: %d, copy: %d\n", nl_vm.config_next_block, nl_vm.config_next_copy);
	//BSP_LED_On(1);
out:
	free(nvm_copy);
 	return ret;
 }

 #else // NL_CONFIG_RAW_ALGO

 int nanolock_save_register_config_blkdev(struct nl_nvm_struct *nvm)
 {
 	char buf[sizeof(nvm->register_config)];
 	int ret = 0;

 	// // Saving the config in buf so the config will always have meaningful data
  // obscure_buffer((char*)&nvm->register_config, sizeof(buf), buf);

 	// ret = blkdev_simple_write(NL_CONFIG_DEVICE, NL_CONFIG_PARTITION, NL_CONFIG_OFFSET, buf, sizeof(buf), true);
 	// if (ret < 0)
 	// 	return ret;

 	// if (nvm->OTPMData != NULL) {
 	// 	obscure_buffer(nvm->OTPMData, NL_OTPM_LEN, nvm->OTPMData);
 	// 	ret = blkdev_simple_write(NL_CONFIG_DEVICE, NL_CONFIG_PARTITION, NL_CONFIG_OFFSET + PAGE_SIZE, (char*)nvm->OTPMData, NL_OTPM_LEN, true);
 	// 	obscure_buffer(nvm->OTPMData, NL_OTPM_LEN, nvm->OTPMData);
 	// }

 	return ret;
 }

 int nanolock_save_config_blkdev(struct nl_nvm_struct *nvm)
 {
 	char buf[sizeof(nvm->config)];
	int ret = 0;

	// // Saving the config in buf so the config will always have meaningful data
	// obscure_buffer((char*)&nvm->config, sizeof(buf), buf);

	// ret = blkdev_simple_write(NL_CONFIG_DEVICE, NL_CONFIG_PARTITION, NL_CONFIG_OFFSET + NL_OTPM_LEN + PAGE_SIZE, buf, sizeof(buf), true);
	// if (ret < 0)
	// 	return ret;

	// obscure_buffer((char*)nvm->event_logs, sizeof(nvm->event_logs), (char*)nvm->event_logs);
	// ret = blkdev_simple_write(NL_CONFIG_DEVICE, NL_CONFIG_PARTITION, NL_CONFIG_OFFSET + NL_OTPM_LEN + 2 * PAGE_SIZE, (char*)nvm->event_logs, sizeof(nvm->event_logs), true);
	// obscure_buffer((char*)nvm->event_logs, sizeof(nvm->event_logs), (char*)nvm->event_logs);
	// if (ret < 0)
	// 	return ret;

 	return ret;
 }

 int nanolock_load_config_blkdev(struct nl_nvm_struct *nvm)
 {
 	int ret = 0;

	// ret = blkdev_simple_read(NL_CONFIG_DEVICE, NL_CONFIG_PARTITION, NL_CONFIG_OFFSET, (char*)&nvm->register_config, sizeof(nvm->register_config));
	// if (ret < 0) {
	// 	pr_warn("Nanolock: failed to read chip config\n");
	// 	return ret;
	// }

	// // Allocate OTPM
	// if (nvm->OTPMData == NULL)
	// {
	// 	nvm->OTPMData = kmalloc(NL_OTPM_LEN, GFP_KERNEL);
	// 	if (nvm->OTPMData == NULL) {
	// 		pr_emerg("Nanolock: Not enough memory!\n");
	// 		return -ENOMEM;
	// 	}
	// }
	// ret = blkdev_simple_read(NL_CONFIG_DEVICE, NL_CONFIG_PARTITION, NL_CONFIG_OFFSET + PAGE_SIZE, (char*)nvm->OTPMData, NL_OTPM_LEN);
	// if (ret < 0) {
	// 	pr_warn("Nanolock: failed to read OTPM\n");
	// 	return ret;
	// }

	// ret = blkdev_simple_read(NL_CONFIG_DEVICE, NL_CONFIG_PARTITION, NL_CONFIG_OFFSET + PAGE_SIZE + NL_OTPM_LEN, (char*)&nvm->config, sizeof(nvm->config));
	// if (ret < 0) {
	// 	pr_warn("Nanolock: failed to read chip config\n");
	// 	return ret;
	// }

	// ret = blkdev_simple_read(NL_CONFIG_DEVICE, NL_CONFIG_PARTITION, NL_CONFIG_OFFSET + 2*PAGE_SIZE + NL_OTPM_LEN, (char*)nvm->event_logs, sizeof(nvm->event_logs));
	// if (ret < 0) {
	// 	pr_warn("Nanolock: failed to read chip logs\n");
	// 	return ret;
	// }

	// obscure_buffer((char*)&nvm->register_config, sizeof(nvm->register_config), (char*)&nvm->register_config);
	// obscure_buffer(nvm->OTPMData, NL_OTPM_LEN, nvm->OTPMData);
	// obscure_buffer((char*)nvm->event_logs, sizeof(nvm->event_logs), (char*)nvm->event_logs);
	// obscure_buffer((char*)&nvm->config, sizeof(nvm->config), (char*)&nvm->config);


 	return ret;
 }

 #endif // NL_CONFIG_RAW_ALGO

// // Saves register config/otpm
 int system_save_register_config(struct nl_nvm_struct *nvm)
 {
 	int ret = 0;

#ifndef NL_CONFIG_RAM

#ifdef NL_UBI_VOLUMES
	nanolock_ubi_disable_ro();
#endif // NL_UBI_VOLUMES

	// Unlock flash to allow write if needed
#ifdef NL_CONFIG_ON_PROTECTED_FLASH
	unlockInternal(nvm, NL_CONFIG_PARTITION_UNLOCKED);

#endif // NL_CONFIG_ON_PROTECTED_FLASH

#ifdef NL_CONFIG_RAW
	ret = nanolock_save_register_config_blkdev(nvm);
#else // NL_CONFIG_RAW
	ret = nanolock_save_register_config_file(nvm);
#endif // NL_CONFIG_RAW

	// Lock flash back
#ifdef NL_CONFIG_ON_PROTECTED_FLASH
	LockInternal(nvm);
#endif // NL_CONFIG_ON_PROTECTED_FLASH

#endif // NL_CONFIG_RAM

 	return ret;
 }

// // Saves current config/logs
int system_save_config(struct nl_nvm_struct *nvm)
{
 	int ret = 0;

#ifndef NL_CONFIG_RAM

	// Unlock flash to allow write if needed
#ifdef NL_CONFIG_ON_PROTECTED_FLASH
	unlockInternal(nvm, NL_CONFIG_PARTITION);

#endif // NL_CONFIG_ON_PROTECTED_FLASH

#ifdef NL_CONFIG_RAW
	ret = nanolock_save_config_blkdev(nvm);
#else // NL_CONFIG_RAW
	ret = nanolock_save_config_file(nvm);
#endif // NL_CONFIG_RAW

	// Lock flash back
#ifdef NL_CONFIG_ON_PROTECTED_FLASH
	LockInternal(nvm);
#endif // NL_CONFIG_ON_PROTECTED_FLASH

#endif // NL_CONFIG_RAM

 	return ret;
 }

 int system_load_config(struct nl_nvm_struct *nvm)
 {
 	int ret = -EINVAL;

#ifndef NL_CONFIG_RAM

#ifdef NL_CONFIG_RAW
	ret = nanolock_load_config_blkdev(nvm);
#else // NL_CONFIG_RAW
	ret = nanolock_load_config_file(nvm);
#endif // NL_CONFIG_RAW
	if (ret < 0) {
		pr_emerg("Nanolock: Failed to load chip config\n");
		return ret;
	}

#endif // NL_CONFIG_RAM

	return ret;
}

 int is_registered_in_nvm(struct nl_nvm_struct *nvm)
 {
	return nvm->register_config.IsInitialized;
 }

 int nanolock_update(struct nl_nvm_struct *nvm, char *image_data, StartOtaParams *params)
 {
 	return 0;
 }

 int system_nvm_read(unsigned int partition, unsigned int offset, char *data, uint32_t data_size)
 {
#if NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
	return mtd_simple_read(partition, offset, data, data_size);
#else // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
	return blkdev_simple_read(NL_CONFIG_DEVICE, partition, offset, data, data_size);
#endif // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 }

 int system_nvm_write(unsigned int partition, unsigned int offset, char *data, uint32_t data_size)
 {
#if NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
	return mtd_simple_write(partition, offset, data, roundup(data_size, NL_WRITE_BLOCK_SIZE));
#else // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
	return blkdev_simple_write(NL_CONFIG_DEVICE, partition, offset, data, data_size, true);
#endif // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 }

 int system_nvm_erase(unsigned int partition, unsigned int offset, uint32_t data_size)
 {
#if NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
	return mtd_simple_erase(partition, offset, roundup(data_size, NL_ERASE_BLOCK_SIZE));
#else // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
	return 0;
#endif // NL_CONFIG_DEVICE == MTD_BLOCK_MAJOR
 }

// ///////////////////////////////////////////////////////////////////////////////////////////
// // Protection
// ///////////////////////////////////////////////////////////////////////////////////////////
#ifdef NL_STATIC_PROTECTION
int nanolock_is_flash_locked_static(unsigned long long addr)
{
	int ret = false;
#if ACTIVE_FLASH_MEMORY_LAYOUT == FLASH_MEMORY_LAYOUT_2M

#elif ACTIVE_FLASH_MEMORY_LAYOUT == FLASH_MEMORY_LAYOUT_4M

#elif ACTIVE_FLASH_MEMORY_LAYOUT == FLASH_MEMORY_LAYOUT_8M
    // Bootloaders
    if (addr <= 0x6000)
        ret = true;
    // Keys
    if (addr >= 0x400000 && addr <= 0x402000)
        ret = true;
    // Image & Swap minimal size
    if (addr >= 0x6000 && addr <= 0x6000 + 0x30000)
        ret = false;
    if (addr >= 0x406000 && addr <= 0x406000 + 0x30000)
        ret = true;
#endif // ACTIVE_FLASH_MEMORY_LAYOUT

    if (ret) {
        printf("Nanolock: protecting nvm at addr %d\n", addr);
    }

    return ret;
}
#endif // NL_STATIC_PROTECTION

int nanolock_is_flash_locked(unsigned long long addr, unsigned long long len)
{
    int ret = 0;//false;
    int partition;
    int page_number;
    unsigned long long last_addr = addr + len;
     unsigned long long  tmp2;
//#ifdef NL_STATIC_PROTECTION
//    return nanolock_is_flash_locked_static(addr);
//#endif // NL_STATIC_PROTECTION


    while(last_addr > addr)
    {

	    partition = address_to_partition(addr);
	   // if (partition < 0)
	    // TODO: fix if needed
	/*#ifdef NL_ALWAYS_PROTECT_REGISTER_CONFIG
		if (is_initialized(&nl_nvm) && partition == NL_CONFIG_PARTITION && addr < nl_vm.config_actual_offset + NL_ERASE_BLOCK_SIZE) {
			pr_warn("Nanolock: protecting nvm type: %d partition %d at addr %llu\n", nvm_type, partition, addr);
			return true;
		}
	#endif // NL_ALWAYS_PROTECT_REGISTER_CONFIG*/

		ret = nanolock_is_locked(partition);
		if (ret) {
//			pr_warn("Nanolock: detected access to protecting nvm partition %d, addr %llx\n", partition, addr);
			// Log write to protected memory
//			BSP_LED_Toggle(0);
			nanolock_log(&nl_nvm, EventType_ProtectedWrite, addr);
			nanolock_increase_counter(&nl_nvm, EventCounters_ProtectedWritesCounter);

			//screen_alert(partition, addr);
			break;
		}
	    addr = nanolock_absolute_address(partition + 1, 0);

	    if(addr == 0)
	    	break;//TBD
    }

    return ret;
}

int nanolock_is_flash_read_locked(unsigned long long addr, unsigned long long len)
{
#ifdef NL_CONFIG_READ_LOCK
    int ret = false;
    unsigned long long last_addr = addr + len;
    unsigned long long chip_conf_start_addr = NL_CONFIG_PARTITION_ABSOLUTE_ADDRESS;
    unsigned long long chip_conf_end_addr = NL_CONFIG_PARTITION_ABSOLUTE_ADDRESS + NL_ERASE_BLOCK_SIZE * (NL_ERASE_BLOCK_AMOUNT + 1);

	if (addr < chip_conf_start_addr && last_addr > chip_conf_start_addr) {
		ret = nanolock_is_read_locked(NL_CONFIG_PARTITION);

	}

	if (chip_conf_start_addr <= addr && addr < chip_conf_end_addr) {
		ret = nanolock_is_read_locked(NL_CONFIG_PARTITION);
	}

	if (ret) {
		pr_warn("Nanolock: read protecting nvm partition %d, addr %llx\n", NL_CONFIG_PARTITION, addr);
		// Log write to protected memory
		nanolock_log(&nl_nvm, EventType_ProtectedWrite, addr);
		nanolock_increase_counter(&nl_nvm, EventCounters_ProtectedWritesCounter);

	}

	 // TODO: fix if needed
	/*#ifdef NL_ALWAYS_PROTECT_REGISTER_CONFIG
		if (is_initialized(&nl_nvm) && partition == NL_CONFIG_PARTITION && addr < nl_vm.config_actual_offset + NL_ERASE_BLOCK_SIZE) {
			pr_warn("Nanolock: protecting nvm type: %d partition %d at addr %llu\n", nvm_type, partition, addr);
			return true;
		}
	#endif // NL_ALWAYS_PROTECT_REGISTER_CONFIG*/

    return ret;

#else // NL_CONFIG_READ_LOCK
	return false;
#endif // NL_CONFIG_READ_LOCK
}

// ///////////////////////////////////////////////////////////////////////////////////////////
// // Perform Swap
// ///////////////////////////////////////////////////////////////////////////////////////////
// #define rtk_le32_to_cpu(x)      ((unsigned int)(x))
// #define HAL_READ32(base, addr)              rtk_le32_to_cpu(*((volatile unsigned int*)(base + addr)))
// #define SPI_FLASH_BASE          0x08000000
// #define OTA1_ADDR 0x6000
// #define OTA2_ADDR 0X406000

// static int mtd_abs_read(unsigned int offset, char *data, uint32_t data_size)
// {
//     return jsom_flash_read(0, offset, data, data_size) == JSOM_SUCCESS ? 0 : -EIO;
// }

// static int mtd_abs_write(unsigned int offset, char *data, uint32_t data_size)
// {
//     int ret;
//     // char *buf;
//     jsom_flash_mem_info_t flash_info;

//     ret = jsom_flash_get_info(0, &flash_info);
//     if (ret != JSOM_SUCCESS) {
//         pr_warn("Nanolock: Failed to open mtd %d\n", ret);
//         return -EIO;
//     }

//     // Sanity check for the write size
//     if (data_size % flash_info.page_size != 0) {
//         pr_warn("Nanolock: mtd write bad params\n");
//         ret = -EINVAL;
//         goto out;
//     }

//     ret = jsom_flash_write(0, offset, data,
//                               data_size) == JSOM_SUCCESS ? 0 : -EIO;
//     if (ret < 0) {
//         pr_warn("Nanolock: Failed to write to mtd %d, offset: %u len: %u\n", ret, offset, data_size);
//         if (ret >= 0)
//             ret = -EIO;
//         goto out;
//     }

//     // pr_info("Nanolock: write mtd offset: %u len: %u\n", offset, data_size);

//     // Check that the flash realy written the data
//     // buf = vmalloc(data_size);
//     // if (buf == NULL) {
//     //     printf("Nanolock: Not enough memory!\n");
//     //     ret = -ENOMEM;
//     //     goto out;
//     // }

//     // ret = mtd_abs_read(offset, buf, data_size);
//     // if (ret < 0) {
//     //     printf("Nanolock: Failed to read from mtd %d\n", ret);
//     //     if (ret >= 0)
//     //         ret = -EIO;
//     //     goto out_free;
//     // }
//     // if (memcmp(buf, data, data_size) != 0) {
//     //     printf("Nanolock: mtd write and read doesn't match\n");
//     //     ret = -EIO;
//     //     goto out_free;
// //     }

// // out_free:
// //     vfree(buf);
// out:
//     return ret;
// }

// static int mtd_abs_erase_len(unsigned int offset, uint32_t len)
// {
//     int ret = 0;
//     int erase_required = 0;
//     char *buf = NULL;
//     jsom_flash_mem_info_t flash_info;

//     ret = jsom_flash_get_info(0, &flash_info);
//     if (ret != JSOM_SUCCESS) {
//         pr_warn("Nanolock: Failed to open mtd %d\n", ret);
//         return -EIO;
//     }

//     // Sanity check for the erase size
//     if (len > flash_info.block_size) {
//         pr_warn("Nanolock: mtd erase bad params\n");
//         ret = -EINVAL;
//         goto out;
//     }

//     // Make sure to erase only if needed
//     buf = jsom_mem_alloc(flash_info.block_size);
//     if (buf == NULL) {
//         ret = -ENOMEM;
//         goto out;
//     }

//     ret = mtd_abs_read(offset, buf, flash_info.block_size);
//     if (ret < 0)
//         goto out_free;
//     if (memcmpb(buf, 0xff, flash_info.block_size) != 0) {
//         erase_required = 1;
//     }

//     if (!erase_required) {
//         pr_warn("Nanolock: block at address %u already erased, skipping\n", offset);
//         goto out_free;
//     }

//     ret = jsom_flash_erase(0, offset, flash_info.block_size) == JSOM_SUCCESS ? 0 : -EIO;
//     if (ret < 0) {
//         pr_warn("Nanolock: Failed to erase mtd(size:%u) offset: %u len: %u err: %d\n", flash_info.size, offset, flash_info.block_size, ret);
//     	goto out_free;
//     }

//     // pr_info("Nanolock: erase mtd offset: %u len: %u\n", offset, flash_info.block_size);

//     ret = mtd_abs_write(offset + len, &buf[len], flash_info.block_size - len);
//     if (ret < 0)
//         pr_warn("Nanolock: Failed to write mtd\n");

// out_free:
//     jsom_mem_free(buf);
// out:
//     return ret;
// }

 int system_perform_swap(struct nl_nvm_struct *nvm, unsigned int image_index)
 {
//     unsigned int cur_ota_index = 0;
//     unsigned int ota2_sig[2];

//     ota2_sig[0] = HAL_READ32(SPI_FLASH_BASE, OTA2_ADDR);
//     ota2_sig[1] = HAL_READ32(SPI_FLASH_BASE, OTA2_ADDR+4);

//     // for(int i = 0; i < 2; i++)
//     //     printf("%x",ota2_sig[i]);
//     // printf("\n");

//     // 8195, 8711
//     if(0x35393138 == ota2_sig[0] && 0x31313738 == ota2_sig[1])
//         cur_ota_index = 2; // OTA2
//     else
//         cur_ota_index = 1; // OTA1

//     // ota2_sig[0] = HAL_READ32(SPI_FLASH_BASE, OTA1_ADDR);
//     // ota2_sig[1] = HAL_READ32(SPI_FLASH_BASE, OTA1_ADDR+4);

//     // for(int i = 0; i < 2; i++)
//     //     printf("%x",ota2_sig[i]);
//     // printf("\n");

//     ota2_sig[0] = 0x35393138;
//     ota2_sig[1] = 0x31313738;

//     /* Current is OTA1 */
//     if (cur_ota_index == 1) {
//         if (image_index == NL_IMAGE_INDEX_1) {
//             pr_info("current is OTA1, select OTA1 \n");
//         } else {
//             pr_info("current is OTA1, select OTA2 \n");
//             unlockInternal(nvm, address_to_partition(OTA2_ADDR));
//             mtd_abs_erase_len(OTA2_ADDR, sizeof(ota2_sig));
//             mtd_abs_write(OTA2_ADDR, (unsigned char*)ota2_sig, sizeof(ota2_sig));
//             LockInternal(nvm);
//             unlockInternal(nvm, address_to_partition(OTA1_ADDR));
//             mtd_abs_erase_len(OTA1_ADDR, sizeof(ota2_sig));
//             LockInternal(nvm);
//         }
//     } else { /* Current is OTA2 */
//         if (image_index == NL_IMAGE_INDEX_1) {
//             pr_info("current is OTA2, select OTA1 \n");
//             unlockInternal(nvm, address_to_partition(OTA1_ADDR));
//             mtd_abs_erase_len(OTA1_ADDR, sizeof(ota2_sig));
//             mtd_abs_write(OTA1_ADDR, (unsigned char*)ota2_sig, sizeof(ota2_sig));
//             LockInternal(nvm);
//             unlockInternal(nvm, address_to_partition(OTA2_ADDR));
//             mtd_abs_erase_len(OTA2_ADDR, sizeof(ota2_sig));
//             LockInternal(nvm);
//         } else {
//             pr_info("current is OTA2, select OTA2 \n");
//         }
//     }

     return 0;
 }


/**
 *  @brief  Read data from flash
 *  @param id              : device id
 *  @param offset          : Offset from begin of flash memory device. It is different from memory address in running application
 *                           Actual memory address equals to start address + offset. Start address for flash memory device could be
 *                           obtained via \ref jsom_flash_get_info
 *  @param data            : Buffer to store read data
 *  @param len             : Number of bytes to read.
 *
 *  @return JSOM_SUCCESS or one of JSOM_ERR_... errors
 */



uint32_t PageToAddress(uint32_t Page)
{
	uint32_t address = (0x08000000 + Page*0x1000);

//	BSP_LED_On(LED3); 


	return address; 
}








///////////////////////////////////
//  MX_USART1_UART_Init(&huart1);

 //  sprintf(TosendSTRING, "%d", buf_len);   

 //    while (HAL_UART_GetState(&huart1) != HAL_UART_STATE_READY)
 //  {
 //  }



 // if(HAL_UART_Transmit_IT(&huart1,(uint8_t *)buf, 30 )!= HAL_OK)
 // {
 //    //BSP_LED_On(LED3);

 //   	Error_Handler();
 // }

 //  while (HAL_UART_GetState(&huart1) != HAL_UART_STATE_READY)
 //  {
 //  }




  /*
  while (HAL_UART_GetState(&huart1) != HAL_UART_STATE_READY)
  {
  }


 if(HAL_UART_Transmit_IT(&huart1,(uint8_t*)(RxBuf), 516 )!= HAL_OK)
 {

   	Error_Handler();
 }

  while (HAL_UART_GetState(&huart1) != HAL_UART_STATE_READY)
  {
  }
*/



 		/*********************************/
 //		 if(HAL_UART_Transmit_IT(&huart1, (uint8_t*)myMSG3,sizeof(myMSG3) )!= HAL_OK)
 //		 {

 // 	 			BSP_LED_On(LED1);  
  		   /* Transfer error in transmission process */
 //  			  Error_Handler();
 //		 }
	/********************************/
/////////////////////////////////////

