#include "mbed.h"

//------------------------------------
// Hyperterminal configuration
// 9600 bauds, 8-bit data, no parity
//------------------------------------

Serial pc(PC_10, PC_11);
 
DigitalOut myled(LED1);
 

#include <stdio.h>
#include <expat.h>

#if defined(__amigaos__) && defined(__USE_INLINE__)
#include <proto/expat.h>
#endif

#ifdef XML_LARGE_SIZE
#if defined(XML_USE_MSC_EXTENSIONS) && _MSC_VER < 1400
#define XML_FMT_INT_MOD "I64"
#else
#define XML_FMT_INT_MOD "ll"
#endif
#else
#define XML_FMT_INT_MOD "l"
#endif

#define BUFFSIZE       2048

char Buff[BUFFSIZE];

int Depth;
int done = 0;

static void XMLCALL
start(void *data, const char *el, const char **attr)
{
  int i;

  for (i = 0; i < Depth; i++)
    pc.printf("  ");

  pc.printf("%s", el);

  for (i = 0; attr[i]; i += 2) {
    pc.printf(" %s=%s",attr[i], attr[i + 1]);
  }

  pc.printf("\r\n");
  Depth++;
}

static void XMLCALL
end(void *data, const char *el)
{
  Depth--;
}


int serial_read(char *buf, int n){
    int len = 0;
    do{
        Buff[len] = pc.getc();
        //pc.printf("\n%x\n", Buff[len]);
        //weak heuristic as end of file replacement
        if( (Buff[len] == '\r' && Buff[len-1] == '\r') ||
            (Buff[len] == '\n' && Buff[len-1] == '\n')){
            done = 1;
            break;
        } 
        len ++;
    } while (len < n);
    return len;
}

int
parse()
{
  char c;
  XML_Parser p = XML_ParserCreate(NULL);
  if (! p) {
    fprintf(stderr, "Couldn't allocate memory for parser\r\n");
    exit(-1);
  }

  XML_SetElementHandler(p, start, end);

  for (;;) {
    int len = 0;
    len = serial_read(Buff, BUFFSIZE);
    if (ferror(stdin)) {
      pc.printf("Read error\r\n");
      return -1;
    }

    if (XML_Parse(p, Buff, len, done) == XML_STATUS_ERROR) {
      pc.printf("Parse error at line %" XML_FMT_INT_MOD "u:\r\n%s\r\n",
              XML_GetCurrentLineNumber(p),
              XML_ErrorString(XML_GetErrorCode(p)));
              pc.printf("OEND\n");
              XML_ParserFree(p);
      return -1;
    }

    if (done)
      break;
  }
  pc.printf("OEND\n");
  XML_ParserFree(p);
  return 0;
}


int main() {
  pc.baud(115200);
  while(1) { 
      parse();
  }
}
