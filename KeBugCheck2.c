void __fastcall ntoskrnnl::KiBugCheckDebugBreak(unsigned int a1)
{
  DbgBreakPointWithStatus(a1);
  JUMPOUT(0x140562B97i64);
}

__int64 __fastcall ntoskrnl::KeBugCheck2(unsigned int a1, __int64 a2, unsigned __int64 a3, __int64 a4, unsigned __int64 a5, __int64 a6)
{
  unsigned __int8 CurrentIrql; // cl
  _DWORD *SchedulerAssist; // r9
  signed __int32 v11; // eax
  signed __int32 v12; // edx
  signed __int32 v13; // ecx
  char v14; // r13
  char v15; // r8
  signed __int32 v16; // eax
  signed __int32 v17; // edx
  signed __int32 v18; // ecx
  _XSAVE_AREA_HEADER *ExtendedSupervisorState; // rcx
  char v20; // r13
  int v21; // ecx
  __int64 v22; // r8
  struct _KPRCB *v23; // rbx
  char *v24; // rcx
  __int64 v25; // rdx
  _CONTEXT *Context; // rax
  __int128 v27; // xmm1
  char v28; // r9
  __int64 v29; // rdx
  unsigned int v30; // ecx
  bool v31; // r14
  int v32; // edi
  __int64 v33; // rsi
  __int64 (__fastcall *v34)(); // r15
  unsigned __int8 v35; // di
  int IsEmptyAffinity; // eax
  __int64 v37; // r9
  __int64 v38; // rax
  __int64 v39; // rsi
  __int64 v40; // rbx
  bool v41; // cf
  int v42; // eax
  int IsSpecialPoolAddress; // eax
  __int64 v44; // rax
  __int64 *v45; // rcx
  unsigned __int64 v46; // rsi
  struct _KTHREAD *v47; // rcx
  _KPROCESS *Process; // rcx
  __int64 v49; // rcx
  unsigned __int8 v50; // cl
  _DWORD *v51; // r8
  int v52; // ecx
  char v53; // di
  unsigned int v54; // eax
  __int64 v55; // rcx
  _CONTEXT *v56; // rax
  char *v57; // rcx
  __int64 v58; // rdx
  __int64 v59; // r8
  __int128 v60; // xmm1
  unsigned int v61; // ebx
  __int64 v62; // rcx
  char v64; // [rsp+41h] [rbp-BFh]
  char v65[2]; // [rsp+42h] [rbp-BEh] BYREF
  int v66; // [rsp+44h] [rbp-BCh]
  bool v67; // [rsp+48h] [rbp-B8h]
  bool v68; // [rsp+49h] [rbp-B7h]
  __int64 v69; // [rsp+50h] [rbp-B0h]
  char v70; // [rsp+58h] [rbp-A8h]
  unsigned __int8 v71; // [rsp+59h] [rbp-A7h]
  char v72; // [rsp+5Ah] [rbp-A6h]
  unsigned int v73; // [rsp+60h] [rbp-A0h] BYREF
  int v74; // [rsp+68h] [rbp-98h]
  __int64 v75; // [rsp+70h] [rbp-90h] BYREF
  unsigned int v76; // [rsp+78h] [rbp-88h] BYREF
  __int64 v77; // [rsp+80h] [rbp-80h] BYREF
  struct _KTHREAD *CurrentThread; // [rsp+88h] [rbp-78h]
  struct _KPRCB *CurrentPrcb; // [rsp+90h] [rbp-70h]
  __int64 (__fastcall *v80)(); // [rsp+98h] [rbp-68h]
  unsigned int Number; // [rsp+A0h] [rbp-60h]
  __int64 v82; // [rsp+A8h] [rbp-58h] BYREF
  __int64 v83; // [rsp+B0h] [rbp-50h] BYREF
  const char *v84; // [rsp+B8h] [rbp-48h]
  const char *v85; // [rsp+C0h] [rbp-40h]
  int v86[68]; // [rsp+D0h] [rbp-30h] BYREF
  char v87[1232]; // [rsp+1E0h] [rbp+E0h] BYREF
  char v88[176]; // [rsp+6B0h] [rbp+5B0h] BYREF

  v73 = a1;
  v69 = a6;
  memset(v86, 0i64, 264i64);
  v88[0] = 0;
  CurrentThread = KeGetCurrentThread();
  v77 = 0i64;
  v80 = KiBugCheckProgress;
  v68 = IopAutoReboot != 0;
  v65[0] = 0;
  LOBYTE(v66) = 0;
  v70 = 0;
  v72 = 0;
  v84 = 0i64;
  v85 = 0i64;
  v75 = 0i64;
  v67 = 1;
  v71 = 0;
  v74 = 0;
  v82 = 0i64;
  v83 = 0i64;
  v76 = 0;
  if ( KeGetCurrentIrql() < 2u )
  {
    CurrentIrql = KeGetCurrentIrql();
    __writecr8(2ui64);
    if ( KiIrqlFlags )
    {
      if ( (KiIrqlFlags & 1) != 0 && CurrentIrql <= 0xFu )
      {
        SchedulerAssist = KeGetCurrentPrcb()->SchedulerAssist;
        SchedulerAssist[5] |= (-1 << (CurrentIrql + 1)) & 4;
      }
    }
  }
  if ( KeGetCurrentThread()->InitialStack )
  {
    v15 = KeQueryCurrentStackInformation(&v76, &v83, &v82);
    v16 = KiBugCheckActive;
    v17 = (16 * KeGetCurrentPrcb()->Number) | 3;
    do
    {
      if ( (v16 & 3) == 3 )
      {
        v14 = 0;
        v64 = 0;
        goto LABEL_18;
      }
      v18 = v16;
      v16 = _InterlockedCompareExchange(&KiBugCheckActive, v17, v16);
    }
    while ( v16 != v18 );
    if ( v15 )
    {
      if ( v76 > 9 || (v21 = 929, !_bittest(&v21, v76)) )
      {
        v22 = v82 - v83;
        if ( (unsigned __int64)(v82 - v83) > 0x6000 )
          v22 = 24576i64;
        memmove(&KiPreBugcheckStackSaveArea, v83, v22);
      }
    }
    v14 = 1;
    v64 = 1;
    goto LABEL_29;
  }
  v11 = KiBugCheckActive;
  v12 = (16 * KeGetCurrentPrcb()->Number) | 3;
  do
  {
    if ( (v11 & 3) == 3 )
    {
      v14 = 0;
      goto LABEL_11;
    }
    v13 = v11;
    v11 = _InterlockedCompareExchange(&KiBugCheckActive, v12, v11);
  }
  while ( v11 != v13 );
  v14 = 1;
LABEL_11:
  v64 = v14;
  if ( v14 )
  {
LABEL_29:
    if ( KiRecoveryCallbackCount <= 0 )
      KiBugcheckOwnerKeepsOthersFrozen = 1;
  }
LABEL_18:
  if ( KeSmapEnabled )
    __asm { stac }
  CurrentPrcb = KeGetCurrentPrcb();
  ExtendedSupervisorState = CurrentPrcb->ExtendedSupervisorState;
  Number = CurrentPrcb->Number;
  KeSaveSupervisorState(ExtendedSupervisorState, KeEnabledSupervisorXStateFeatures | 0x100);
  if ( !qword_140C226C0 )
    goto LABEL_21;
  if ( PopSimulateHiberBugcheck )
    PoPowerDownActionInProgress = 0;
  if ( *(_BYTE *)(qword_140C226C0 + 3) )
  {
    if ( v14 )
    {
      DbgPrintEx(
        101i64,
        0i64,
        "\n"
        "A bugcheck occurred during the late stages of hibernate suspend or resume.\n"
        "Due to verification temporarily enabled by Po during this time,\n"
        "regular bugcheck processing may not work.\n"
        "\n");
      if ( v73 == 10 )
        DbgPrintEx(
          101i64,
          0i64,
          "Memory was accessed during this time that was not properly marked\n"
          "for the boot phase of hibernate! Check the callstack and parameters\n"
          "to find the pages that need to be marked.\n"
          "\n");
    }
    v80 = 0i64;
    v20 = 1;
  }
  else
  {
LABEL_21:
    v20 = 0;
  }
  v23 = CurrentPrcb;
  v24 = v87;
  v25 = 9i64;
  Context = CurrentPrcb->Context;
  do
  {
    *(_OWORD *)v24 = *(_OWORD *)&Context->P1Home;
    *((_OWORD *)v24 + 1) = *(_OWORD *)&Context->P3Home;
    *((_OWORD *)v24 + 2) = *(_OWORD *)&Context->P5Home;
    *((_OWORD *)v24 + 3) = *(_OWORD *)&Context->ContextFlags;
    *((_OWORD *)v24 + 4) = *(_OWORD *)&Context->SegGs;
    *((_OWORD *)v24 + 5) = *(_OWORD *)&Context->Dr1;
    *((_OWORD *)v24 + 6) = *(_OWORD *)&Context->Dr3;
    v24 += 128;
    v27 = *(_OWORD *)&Context->Dr7;
    Context = (_CONTEXT *)((char *)Context + 128);
    *((_OWORD *)v24 - 1) = v27;
    --v25;
  }
  while ( v25 );
  v28 = v64;
  *(_OWORD *)v24 = *(_OWORD *)&Context->P1Home;
  *((_OWORD *)v24 + 1) = *(_OWORD *)&Context->P3Home;
  *((_OWORD *)v24 + 2) = *(_OWORD *)&Context->P5Home;
  *((_OWORD *)v24 + 3) = *(_OWORD *)&Context->ContextFlags;
  *((_OWORD *)v24 + 4) = *(_OWORD *)&Context->SegGs;
  if ( !v64 )
  {
    v31 = 1;
    v35 = v71;
    v34 = v80;
    goto LABEL_155;
  }
  IoNotifyDump(4i64);
  if ( ViVerifierEnabled )
    VfNotifyVerifierOfEvent(2i64);
  v30 = v73;
  if ( v73 == 229 )
  {
    KiScanBugCheckCallbackList();
    ((void (__fastcall *)(_QWORD))off_140C01EF8[0])(0i64);
    HalReturnToFirmware(3i64);
  }
  qword_140C2BC08 = a2;
  qword_140C2BC10 = a3;
  if ( v73 == -1073741103 )
    v30 = 195;
  qword_140C2BC18 = a4;
  KiBugCheckData = v30;
  v73 = v30;
  qword_140C2BC20 = a5;
  if ( v30 > 0xD8 )
  {
    if ( v30 == 234 )
    {
      KiBugCheckDriver = a4;
      goto LABEL_57;
    }
    if ( v30 == 239 )
    {
      v32 = 1;
    }
    else
    {
      if ( v30 == 252 )
      {
LABEL_124:
        v33 = v69;
        if ( !v69 )
        {
          if ( !a4 || (a4 & 3) != 0 )
            goto LABEL_57;
          v33 = a4;
          v69 = a4;
        }
        if ( v30 != 142 )
        {
          v29 = 1i64;
          v49 = *(_QWORD *)(v33 + 360);
          v75 = v49;
          if ( KeGetCurrentThread()->ApcStateIndex == 1 )
          {
            v32 = 0;
            if ( (unsigned __int64)(v49 - qword_140C504F0) < 0x8000000000i64
              && (HIDWORD(KeGetCurrentThread()->ApcState.Process[2].Header.WaitListHead.Flink) & 0x1000) == 0 )
            {
              LOBYTE(v32) = 1;
              v66 = v32;
              goto LABEL_136;
            }
          }
        }
LABEL_57:
        v31 = 1;
LABEL_58:
        LOBYTE(v32) = v66;
LABEL_59:
        v33 = v69;
        goto LABEL_60;
      }
      if ( v30 == 317 )
      {
        v74 = 8;
        goto LABEL_57;
      }
      if ( v30 != 335 )
      {
        if ( v30 == 456 )
          v72 = 1;
        goto LABEL_57;
      }
      if ( a3 < 0x100 && a5 )
      {
        v47 = CurrentThread;
        if ( *(_QWORD *)(a5 + 8) )
          v47 = *(struct _KTHREAD **)(a5 + 8);
        CurrentThread = v47;
      }
      Process = KeGetCurrentThread()->ApcState.Process;
      v32 = HIDWORD(Process[2].Header.WaitListHead.Flink) >> 12;
      LOBYTE(v32) = (HIDWORD(Process[2].Header.WaitListHead.Flink) & 0x1000) == 0;
    }
    v31 = 1;
    v66 = v32;
    goto LABEL_59;
  }
  switch ( v30 )
  {
    case 0xD8u:
      v77 = a2;
      KiBugCheckDriver = a2 + 88;
      goto LABEL_57;
    case 0xAu:
      if ( a5 >= ExPoolCodeStart && a5 < ExPoolCodeEnd )
      {
        KiBugCheckData = 197i64;
        goto LABEL_57;
      }
      KiPcToFileHeader(a5, &v77, 0i64, v65);
      v29 = 1i64;
      if ( v65[0] == 1 )
      {
        if ( KiPcToFileHeader(a2, &v77, 1i64, v65) )
        {
          KiBugCheckData = 211i64;
          KiBugCheckDriver = v77 + 88;
        }
        else
        {
          KiBugCheckDriver = MmLocateUnloadedDriver(a2);
          if ( KiBugCheckDriver )
            KiBugCheckData = 212i64;
        }
        goto LABEL_57;
      }
      KiBugCheckData = 209i64;
LABEL_88:
      v31 = 1;
      goto LABEL_58;
    case 0x4Cu:
      v84 = (const char *)a4;
      LOBYTE(v66) = 1;
      v45 = &qword_140C2BC08;
      v70 = 1;
      v46 = a3 - (_QWORD)&qword_140C2BC08;
      KiBugCheckData = (unsigned int)a2;
      v85 = (const char *)a5;
      do
      {
        *v45 = *(__int64 *)((char *)v45 + v46);
        ++v45;
      }
      while ( (__int64)v45 < (__int64)&unk_140C2BC28 );
      goto LABEL_57;
  }
  if ( v30 != 80 )
  {
    if ( v30 == 123 )
    {
      v29 = 1i64;
      v67 = (a4 & 1) == 0;
      v31 = (a4 & 2) == 0;
      goto LABEL_58;
    }
    if ( v30 != 142 && v30 != 190 )
    {
      if ( v30 == 203 )
        v75 = a2;
      goto LABEL_57;
    }
    goto LABEL_124;
  }
  v38 = v69;
  v39 = 0i64;
  if ( !v69 )
  {
    if ( !a4 || (a4 & 3) != 0 )
    {
      v65[0] = 1;
      goto LABEL_84;
    }
    v38 = a4;
    v69 = a4;
  }
  v75 = *(_QWORD *)(v38 + 360);
  v40 = v75;
  qword_140C2BC18 = v75;
  v39 = KiPcToFileHeader(v75, &v77, 0i64, v65);
  if ( KeGetCurrentThread()->ApcStateIndex == 1 )
  {
    v41 = (unsigned __int64)(v40 - qword_140C504F0) < 0x8000000000i64;
    v23 = CurrentPrcb;
    if ( v41 )
    {
      v42 = (unsigned __int8)v66;
      if ( (HIDWORD(KeGetCurrentThread()->ApcState.Process[2].Header.WaitListHead.Flink) & 0x1000) == 0 )
        v42 = 1;
      v66 = v42;
    }
  }
  else
  {
    v23 = CurrentPrcb;
  }
LABEL_84:
  IsSpecialPoolAddress = MmIsSpecialPoolAddress(a2);
  v29 = 1i64;
  if ( IsSpecialPoolAddress == 1 )
  {
    v44 = 213i64;
    if ( v65[0] == 1 )
      v44 = 204i64;
    KiBugCheckData = v44;
    goto LABEL_88;
  }
  if ( v75 == a2
    && (unsigned __int64)(a2 - qword_140C504F0) < 0x8000000000i64
    && (unsigned __int64)CurrentThread->Teb - 1 > 0xFFFF7FFFFFFFFFFEui64 )
  {
    KiBugCheckData = 207i64;
    goto LABEL_88;
  }
  if ( !v39 )
  {
    KiBugCheckDriver = MmLocateUnloadedDriver(a2);
    if ( KiBugCheckDriver )
      KiBugCheckData = 206i64;
    goto LABEL_57;
  }
  LOBYTE(v32) = v66;
  v33 = v69;
LABEL_136:
  v31 = 1;
LABEL_60:
  if ( !(_DWORD)WheapHighIrqlLogSelHandler )
  {
    WheapSelLogSetNtSchedulerAvailabilityNoLock();
    if ( (unsigned __int8)IpmiHwContextInitialized(&WheaIpmiContext) )
      IpmiLibAddSelBugcheckRecord();
  }
  BugCheckProgressEfiSafeToCall = KiBugCheckData != 265;
  if ( v31 )
  {
    LOBYTE(v29) = v20;
    KiCollectTriageDumpDataBlocks(KiBugCheckData, v29);
  }
  v34 = v80;
  if ( v68 )
  {
    qword_140C2BC50 = (__int64)v80;
    KiCrashDumpContext = (__int64)v87;
    qword_140C2BC48 = (__int64)CurrentThread;
    qword_140C2BC58 = v33;
    byte_140C2BC60 = v32;
    KiAttemptBugcheckRecovery();
  }
  v35 = 1;
  KiBugcheckOwnerKeepsOthersFrozen = 1;
  off_140C01F18[0]();
  HvlEnlightenments &= 0x2000u;
  IoSaveBugCheckProgress(96i64);
  IsEmptyAffinity = KeIsEmptyAffinityEx(KiNmiInProgress);
  ((void (__fastcall *)(bool))off_140C01CE8[0])(IsEmptyAffinity == 0);
  KiFilterBugCheckInfo(&v73, &KiBugCheckData);
  if ( CrashdmpDumpBlock && v31 )
    v35 = 0;
  HvlLogGuestCrashInformation(KiBugCheckData, qword_140C2BC08, qword_140C2BC10, qword_140C2BC18, qword_140C2BC20, v35);
  if ( KiBugCheckDriver )
  {
    KiBugCheckUnicodeToAnsi(KiBugCheckDriver, v88);
  }
  else if ( v75 )
  {
    LOBYTE(v37) = 1;
    KiDumpParameterImages(v88, &v75, 1i64, v37);
  }
  if ( !KdPitchDebugger )
    qword_140C021B8 = (__int64)v87;
  if ( (unsigned __int8)KiBugCheckShouldEnterPostBugCheckDebugger(v73, 0i64) )
  {
    if ( !v23->NmiActive )
    {
      DbgPrintEx(
        101i64,
        0i64,
        "\n*** Fatal System Error: 0x%08lx\n                       (0x%p,0x%p,0x%p,0x%p)\n\n",
        (unsigned int)KiBugCheckData,
        (const void *)qword_140C2BC08,
        (const void *)qword_140C2BC10,
        (const void *)qword_140C2BC18,
        (const void *)qword_140C2BC20);
      if ( KiBugCheckDriver )
        DbgPrintEx(101i64, 0i64, "Driver at fault: %s.\n", v88);
      if ( v70 )
      {
        if ( v84 )
          DbgPrintEx(101i64, 0i64, v84);
        if ( v85 )
          DbgPrintEx(101i64, 0i64, v85);
      }
    }
    if ( KdDebuggerEnabled && !KdDebuggerNotPresent )
      KiBugCheckDebugBreak(3i64);
  }
  v28 = v64;
LABEL_155:
  _disable();
  v50 = KeGetCurrentIrql();
  __writecr8(0xFui64);
  if ( KiIrqlFlags && (KiIrqlFlags & 1) != 0 && v50 <= 0xFu )
  {
    v51 = KeGetCurrentPrcb()->SchedulerAssist;
    v51[5] |= (-1 << (v50 + 1)) & 0xFFFC;
  }
  if ( v28 )
  {
    if ( (unsigned int)KeNumberProcessors_0 > 1 && !KiHypervisorInitiatedCrashDump )
    {
      KiSetDebuggerOwner(v23);
      v86[0] = 2097153;
      memset(&v86[1], 0i64, 260i64);
      KiCopyAffinityEx(v86, 32i64, &KeActiveProcessors);
      KeRemoveProcessorAffinityEx(v86, v23->Number);
      KiSendFreeze(v86, 0i64);
      KeStallExecutionProcessor(1000000i64);
    }
    IoSaveInitialBugCheckProgress((unsigned int)KiBugCheckData, qword_140C2BC08);
    IoSaveBugCheckProgress(1i64);
    if ( v20 )
    {
      v53 = v67;
    }
    else
    {
      v52 = v74;
      if ( v35 )
        v52 = v74 | 4;
      v53 = v67;
      v54 = v52 | 2;
      if ( v68 )
        v54 = v52;
      v55 = v54 | 1;
      if ( v67 )
        v55 = v54;
      KiDisplayBlueScreen(v55);
    }
    HvlPrepareForRootCrashdump(1i64);
    if ( !v20 )
    {
      KiInvokeBugCheckEntryCallbacks(1i64, 0i64, 0i64);
      KiInvokeBugCheckEntryCallbacks(8i64, 0i64, 0i64);
    }
    if ( !KdDebuggerEnabled && !KdPitchDebugger )
      KdEnableDebuggerWithLock(0i64);
    v56 = v23->Context;
    v57 = v87;
    v58 = 9i64;
    v59 = 128i64;
    do
    {
      *(_OWORD *)&v56->P1Home = *(_OWORD *)v57;
      *(_OWORD *)&v56->P3Home = *((_OWORD *)v57 + 1);
      *(_OWORD *)&v56->P5Home = *((_OWORD *)v57 + 2);
      *(_OWORD *)&v56->ContextFlags = *((_OWORD *)v57 + 3);
      *(_OWORD *)&v56->SegGs = *((_OWORD *)v57 + 4);
      *(_OWORD *)&v56->Dr1 = *((_OWORD *)v57 + 5);
      *(_OWORD *)&v56->Dr3 = *((_OWORD *)v57 + 6);
      v56 = (_CONTEXT *)((char *)v56 + 128);
      v60 = *((_OWORD *)v57 + 7);
      v57 += 128;
      *(_OWORD *)&v56[-1].LastExceptionToRip = v60;
      --v58;
    }
    while ( v58 );
    *(_OWORD *)&v56->P1Home = *(_OWORD *)v57;
    *(_OWORD *)&v56->P3Home = *((_OWORD *)v57 + 1);
    *(_OWORD *)&v56->P5Home = *((_OWORD *)v57 + 2);
    *(_OWORD *)&v56->ContextFlags = *((_OWORD *)v57 + 3);
    *(_OWORD *)&v56->SegGs = *((_OWORD *)v57 + 4);
    if ( v31 )
    {
      KdDecodeDataBlock(v57, 0i64, 128i64);
      qword_140C2BC48 = (__int64)CurrentThread;
      qword_140C2BC58 = v69;
      byte_140C2BC60 = v66;
      KiCrashDumpContext = (__int64)v87;
      qword_140C2BC50 = (__int64)v34;
      KiBugCheckWriteCrashDump(&KiCrashDumpContext);
    }
  }
  else
  {
    v61 = KiBugCheckActive;
    KiHandleMultipleBugchecksDuringRecovery((unsigned int)KiBugCheckActive);
    if ( Number != v61 >> 4 )
    {
      while ( 1 )
      {
        if ( KeGetPcr()->Prcb.CombinedNmiMceActive && KeGetCurrentPrcb()->IpiFrozen == 5 )
          KiFreezeTargetExecution(0i64, 0i64);
        _mm_pause();
      }
    }
    if ( KiHypervisorInitiatedCrashDump || (v61 & 0xC) >= 8 )
    {
      while ( 1 )
        off_140C01C28();
    }
    IoSetBugCheckProgressFlag(0x20000i64);
    _InterlockedExchangeAdd(&KiBugCheckActive, 4u);
    if ( (v61 & 0xC) != 0 )
      KiBugCheckDebugBreak(4i64);
    v53 = v67;
  }
  HvlResumeFromRootCrashdump(0i64, v58, v59);
  IoSaveBugCheckProgress(99i64);
  if ( !v20 )
    KiScanBugCheckCallbackList();
  off_140C01F08[0]();
  IoSaveBugCheckProgress(4i64);
  if ( v68 )
  {
    KiResumeForReboot = 1;
    KiSendThawExecution(0i64);
    KiBugcheckUnloadDebugSymbols();
    ((void (__fastcall *)(_QWORD))off_140C01EF8[0])(0i64);
    if ( PoPowerDownActionInProgress && !PoPowerResetActionInProgress
      || PoModernStandbyActionInProgress
      || v72
      || (v62 = 3i64, !v53) )
    {
      v62 = 1i64;
    }
    HalReturnToFirmware(v62);
  }
  return KiBugCheckDebugBreak(4i64);
}
