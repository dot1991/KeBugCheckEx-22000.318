__int64 ntoskrnl::KeBugCheckEx(unsigned __int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, ...)
{
  unsigned __int64 v5; // kr00_8
  _CONTEXT *Context; // r10
  va_list v7; // r8
  __int64 (*v8)(unsigned __int64, __int64, __int64, __int64, __int64, ...); // r9
  signed __int8 CurrentIrql; // al
  unsigned __int64 v10; // rcx
  __int64 v12; // [rsp+8h] [rbp-10h]
  unsigned __int64 v13; // [rsp+10h] [rbp-8h]
  void *retaddr; // [rsp+18h] [rbp+0h] BYREF
  va_list va; // [rsp+48h] [rbp+30h] BYREF

  va_start(va, a5);
  v5 = __readeflags();
  v13 = v5;
  _disable();
  RtlCaptureContext(KeGetCurrentPrcb()->Context);
  KiSaveProcessorControlState(&KeGetCurrentPrcb()->ProcessorState);
  Context = KeGetCurrentPrcb()->Context;
  Context->Rcx = a1;
  *(_QWORD *)&Context->EFlags = v13;
  if ( &loc_140415579 == retaddr )
  {
    va_copy(v7, va);
    v8 = (__int64 (*)(unsigned __int64, __int64, __int64, __int64, __int64, ...))KeBugCheck;
  }
  else
  {
    v7 = &retaddr;
    v8 = KeBugCheckEx;
  }
  Context->Rsp = (unsigned __int64)v7;
  Context->Rip = (unsigned __int64)v8;
  CurrentIrql = KeGetCurrentIrql();
  __writegsbyte(0x82D8u, CurrentIrql);
  if ( CurrentIrql < 2 )
    __writecr8(2ui64);
  if ( (v5 & 0x200) != 0 )
    _enable();
  _InterlockedIncrement(&KiHardwareTrigger);
  v10 = a1;
  v12 = 0i64;
  if ( &loc_140415579 != retaddr )
    KeBugCheck2(a1, a2, a3, a4, a5, 0i64);
  return KeBugCheck2(v10, 0i64, 0i64, 0i64, 0i64, v12);
}
