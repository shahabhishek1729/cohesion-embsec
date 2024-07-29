// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#include "bootloader.h"

// Hardware Imports
#include "inc/hw_memmap.h"    // Peripheral Base Addresses
#include "inc/hw_types.h"     // Boolean type
#include "inc/tm4c123gh6pm.h" // Peripheral Bit Masks and Registers
// #include "inc/hw_ints.h" // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h"     // FLASH API
#include "driverlib/interrupt.h" // Interrupt API
#include "driverlib/sysctl.h"    // System control API (clock/reset)

// Application Imports
#include "driverlib/gpio.h"
#include "uart/uart.h"

// Cryptography Imports
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/rsa.h"

// Forward Declarations
void load_firmware(void);
void boot_firmware(void);
void uart_write_hex_bytes(uint8_t, uint8_t *, uint32_t);

// Firmware Constants
#define METADATA_BASE 0xFC00 // base address of version and firmware size in Flash
#define FW_BASE 0x10000      // base address of firmware in Flash

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Constraint Constants
/*
    30000 max firmware
     1000 max message
        2 version number
        2 message length, 
        2 firmware length
        1 null byte
+
---------------------
=   31008 (with padding)
       16 nonce
       16 tag
+
---------------------
   ~31050 (for good measure)
*/

#define MAX_SENT_LEN 31050 
#define MAX_MESSAGE_LEN 1000

// Device metadata
uint16_t * fw_version_address = (uint16_t *)METADATA_BASE;
uint16_t * fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint16_t * fw_release_message_address; 

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];


// prevent gdb debugging
#include <stdint.h>
#include "inc/hw_types.h"
#include "inc/hw_flash.h"
#include "inc/hw_memmap.h"
#include "driverlib/sysctl.h"
#include "driverlib/flash.h"

void disableDebugging(void){
    // Write the unlock value to the flash memory protection registers
    HWREG(FLASH_FMPRE0) = 0xFFFFFFFF;
    HWREG(FLASH_FMPPE0) = 0xFFFFFFFF;

    // Disable the debug interface by writing to the FMD and FMC registers
    HWREG(FLASH_FMD) = 0xA4420004;
    HWREG(FLASH_FMC) = FLASH_FMC_WRKEY | FLASH_FMC_COMT;
 }

// Delay to allow time to connect GDB
// green LED as visual indicator of when this function is running
void debug_delay_led() {

    // Enable the GPIO port that is used for the on-board LED.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
    }

    // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
    // enable the GPIO pin for digital function.
    GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

    // Turn on the green LED
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3);

    // Wait
    SysCtlDelay(SysCtlClockGet() * 2);

    // Turn off the green LED
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0x0);
}


int main(void) {

    // prevent debugging with gdb
    disableDebugging();

    // Enable the GPIO port that is used for the on-board LED.
    SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

    // Check if the peripheral access is enabled.
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
    }

    // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
    // enable the GPIO pin for digital function.
    GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

    debug_delay_led();

    initialize_uarts(UART0);

    uart_write_str(UART0, "Welcome to the BWSI Vehicle Update Service!\n");
    uart_write_str(UART0, "Send \"U\" to update, and \"B\" to run the firmware.\n");

    int resp;
    while (1) {
        uint32_t instruction = uart_read(UART0, BLOCKING, &resp);

        if (instruction == UPDATE) {
            uart_write_str(UART0, "U");
            load_firmware();
            
            uart_write_str(UART0, "Loaded new firmware.\n");
            nl(UART0);
        } else if (instruction == BOOT) {
            uart_write_str(UART0, "B");
            uart_write_str(UART0, "Booting firmware...\n");
            boot_firmware();
        }
    }
}

/*
   Load firmware into buffer
   Return actual buffer size
*/
uint32_t load_firmware_buffer(uint8_t *buffer, uint32_t buffer_size) {
    uint32_t rcv = 0;
    int frame_length = 0;
    uint32_t buff_idx = 0;
    int read = 0;

    while (1) {
        // Get two bytes for the length.
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length = (int)rcv << 8;
        rcv = uart_read(UART0, BLOCKING, &read);
        frame_length += (int)rcv;

        // If at end of all sent bytes, stop loop
        if (frame_length == 0) {
            uart_write(UART0, OK);
            break;
        }

        // Ensure buffer is large enough
        if (buff_idx + frame_length > buffer_size) {
            uart_write(UART0, ERROR); // Buffer overflow
            return 0;
        }

        // Get the number of bytes specified
        for (int i = 0; i < frame_length; ++i) {
            buffer[buff_idx] = uart_read(UART0, BLOCKING, &read);
            buff_idx += 1;
        }

        // Acknowledge frame
        uart_write(UART0, OK);
    }

    return buff_idx;
}
/*
    Decrypt and Authenticate buffer contents
    Return error code
*/

uint8_t decrypt_buffer(uint8_t *buffer, uint32_t buffer_len) {
    // where buffer is
    uint32_t blob_start = 0;

    // Define the byte array using uint8_t
    // TODO: Incorporate randomly generated key so I don't get flamed on monday

    // if the length of the buffer is this small, something went SERIOUSLY wrong...
    if (buffer_len < (IV_LEN + 16 + 1)) { 
        SysCtlReset();                  
        return (uint8_t) -1;
    }

    const uint8_t aes_key[] = {
        'S', 'e', 'g', 'm', 'e', 'n', 't', 'a', 't', 'i', 'o', 'n', ' ', 
        'f', 'a', 'u', 'l', 't', ' ', '(', 'c', 'o', 'r', 'e', ' ', 
        'd', 'u', 'm', 'p', 'e', 'd', ')'
    };

    // read iv
    uint8_t iv[IV_LEN];

    for (int i = 0; i < IV_LEN; i++) {
        iv[i] = buffer[blob_start + i];
    }

    blob_start += IV_LEN;

    // read tag
    uint8_t tag[16]; // the length of the generated tag is 16 bytes

    for (int i = 0; i < 16; i++) {
        tag[i] = buffer[blob_start+i];
    }

    blob_start += 16;

    /*********************START DECRYPTION PROCESS*********************/

    // Initialize AES-GCM decryption context
    Aes aes;
    wc_AesGcmSetKey(&aes, (const byte *) aes_key, 32); // length of aes key is 32

    // Perform decryption
    int gcm_code = wc_AesGcmDecrypt(
        &aes,                            // AES context
        (buffer + blob_start),           // Output buffer for plaintext
        (buffer + blob_start),           // Input ciphertext
        buffer_len-blob_start,           // Length of ciphertext
        iv,                              // Nonce/IV
        IV_LEN,                          // Size of nonce/IV
        tag,                             // Authentication tag
        16,                              // Size of authentication tag
        NULL,                            // No additional authenticated data (AAD)
        0                                // Size of AAD
    );

    // Reject if not authenticated
    if (gcm_code != 0) {
        SysCtlReset();
        return -1;
    }

    // Free AES context
    wc_AesFree(&aes);


    // everything went well
    return (uint8_t) 0;
}

/*
    Load to flash from buffer
*/

void load_firmware(void) {
    uint32_t version;
    uint32_t fw_size;

    // load contents to buffer
    uint8_t send_buff[MAX_SENT_LEN];
    uint32_t send_size = load_firmware_buffer(send_buff, (uint32_t) MAX_SENT_LEN);

    // decrypt buffer
    decrypt_buffer(send_buff, send_size);

    // where blob starts
    uint32_t blob_start = IV_LEN + 16; // how it was defined in decrypt

    // get version
    version = (uint32_t) send_buff[0+blob_start];
    version |= (uint32_t) send_buff[1+blob_start] << 8;

    // get size
    fw_size = (uint32_t) send_buff[2+blob_start];
    fw_size |= (uint32_t) send_buff[3+blob_start] << 8;

    // keep track of flash page
    uint32_t page_addr = FW_BASE;

    // Compare to old version and abort if older (note special case for version 0).
    // If no metadata available (0xFFFF), accept version 2
    uint16_t old_version = *fw_version_address;
    if (old_version == 0xFFFF) {
        old_version = 2;
    }

    if (version < old_version) {
        uart_write(UART0, ERROR); // Reject the metadata.
        SysCtlReset();            // Reset device
        return;
    } 
  
    // Write new firmware size and version to Flash
    // Create 32 bit word for flash programming, version is at lower address, size is at higher address
    uint32_t metadata = ((fw_size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash((uint8_t *) METADATA_BASE, (uint8_t *)(&metadata), 4);

    // compute start of firmware
    uint32_t fw_start = 36; // 36 = 2 version + 2 fw_size + 16 IV + 16 Tag

    /*********************** PROGRAM FIRMWARE TO FLASH ********************* */
    // store flash page
    uint32_t flash_idx = 0;

    for (int i = 0; i < send_size; i++) {
        data[flash_idx] = send_buff[fw_start + i];

        // check if flash buffer is full or if last frame is done
        if ((flash_idx) == FLASH_PAGESIZE || (i == (send_size-1))) {
            // Try to write flash and check for error
            if (program_flash((uint8_t *) page_addr, data, flash_idx)) {
                uart_write(UART0, ERROR); // Reject the firmware
                SysCtlReset();            // Reset device
                return;
            }

            // Update to next page
            page_addr += FLASH_PAGESIZE;
            flash_idx = 0;
        }

        flash_idx++;
    }
}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of bytes to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(void* page_addr, unsigned char * data, unsigned int data_len) {
    uint32_t word = 0;
    int ret;
    int i;

    // Erase next FLASH page
    FlashErase((uint32_t) page_addr);

    // Clear potentially unused bytes in last word
    // If data not a multiple of 4 (word size), program up to the last word
    // Then create temporary variable to create a full last word
    if (data_len % FLASH_WRITESIZE) {
        // Get number of unused bytes
        int rem = data_len % FLASH_WRITESIZE;
        int num_full_bytes = data_len - rem;

        // Program up to the last word
        ret = FlashProgram((unsigned long *)data, (uint32_t) page_addr, num_full_bytes);
        if (ret != 0) {
            return ret;
        }

        // Create last word variable -- fill unused with 0xFF
        for (i = 0; i < rem; i++) {
            word = (word >> 8) | (data[num_full_bytes + i] << 24); // Essentially a shift register from MSB->LSB
        }
        for (i = i; i < 4; i++) {
            word = (word >> 8) | 0xFF000000;
        }

        // Program word
        return FlashProgram(&word, (uint32_t) page_addr + num_full_bytes, 4);
    } else {
        // Write full buffer of 4-byte words
        return FlashProgram((unsigned long *)data, (uint32_t) page_addr, data_len);
    }
}

void boot_firmware(void) {
    // Check if firmware loaded
    int fw_present = 0;
    for (uint8_t* i = (uint8_t*) FW_BASE; i < (uint8_t*) FW_BASE + 20; i++) {
        if (*i != 0xFF) {
            fw_present = 1;
        }
    }

    if (!fw_present) {
        uart_write_str(UART0, "No firmware loaded.\n");
        SysCtlReset();            // Reset device
        return;
    }

    // compute the release message address, and then print it
    uint16_t fw_size = *fw_size_address;
    fw_release_message_address = (uint8_t *)(FW_BASE + fw_size);

    uart_write_str(UART0, (char *) fw_release_message_address);

    // Boot the firmware
    __asm("LDR R0,=0x10001\n\t"
          "BX R0\n\t");
}

void uart_write_hex_bytes(uint8_t uart, uint8_t * start, uint32_t len) {
    for (uint8_t * cursor = start; cursor < (start + len); cursor += 1) {
        uint8_t data = *((uint8_t *)cursor);
        uint8_t right_nibble = data & 0xF;
        uint8_t left_nibble = (data >> 4) & 0xF;
        char byte_str[3];
        if (right_nibble > 9) {
            right_nibble += 0x37;
        } else {
            right_nibble += 0x30;
        }
        byte_str[1] = right_nibble;
        if (left_nibble > 9) {
            left_nibble += 0x37;
        } else {
            left_nibble += 0x30;
        }
        byte_str[0] = left_nibble;
        byte_str[2] = '\0';

        uart_write_str(uart, byte_str);
        uart_write_str(uart, " ");
    }
}



