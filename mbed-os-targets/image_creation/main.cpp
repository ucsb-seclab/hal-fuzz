#include "mbed.h"

//InterruptIn button(USER_BUTTON);
DigitalOut led1(LED1);

#define SLEEP_TIME                  250
#define PRINT_AFTER_N_LOOPS         10

void evil_read() {
    char buf[16];
    int i = 0;
    char c;
    puts("Please enter the secret code:");
    while (1) {
        c = getc(stdin);
        buf[i] = c;
        putc(c, stdin);
        if (c == '\r') {
            buf[i] = 0;
            break;
        }
        i++;
    }
    puts("Code accepted");

    ((void(*)(void))(0x61616161))();
}

// main() runs in its own thread in the OS
int main()
{
    // Assign functions to button
    //button.fall(&pressed);
    //button.rise(&released);
    
    // 1. blink an LED
    for(int i = 0; i < PRINT_AFTER_N_LOOPS; ++i) {
        // Blink LED and wait 0.5 seconds
        led1 = !led1;
        wait_ms(SLEEP_TIME);
    }

    // 2. Write out to UART
    puts("Welcome!");

    // 3. Wait for specific input
    int found = 0;
    while(1) {
        if(getc(stdin)=='P') {
        if(getc(stdin)=='A') {
        if(getc(stdin)=='S') {
        if(getc(stdin)=='S') {
        if(getc(stdin)=='W') {
        if(getc(stdin)=='O') {
        if(getc(stdin)=='R') { 
        if(getc(stdin)=='D') {
            break;
        }
        }    
        }    
        }    
        }    
        }    
        }
	}
    }

    // Crash
    evil_read();
}
