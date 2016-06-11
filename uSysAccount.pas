unit uSysAccount;

interface

uses
  WinSvc,
  SvcMgr,
  Winapi.Windows,
  System.SysUtils,
  TlHelp32,
  System.Classes;

type
  TsSysAccount = class(TService)
    procedure ServiceExecute(Sender: TService);
  private
    lpApplicationName,
    lpCommandLine,
    lpCurrentDirectory: PWideChar;
  public
    function GetServiceController: TServiceController; override;
  end;

procedure CreateProcessAsSystem(const lpApplicationName: PWideChar;
                              const lpCommandLine:PWideChar = nil;
                              const lpCurrentDirectory: PWideChar  = nil);
var
   sSysAccount: TsSysAccount;

implementation

{$R *.dfm}

function WTSQueryUserToken(SessionId: ULONG; var phToken: THandle): BOOL; stdcall; external 'Wtsapi32.dll';


type
    TServiceApplicationEx = class(TServiceApplication)
    end;
    TServiceApplicationHelper = class helper for TServiceApplication
    public
      procedure ServicesRegister(Install, Silent: Boolean);
    end;

function IsUserAnAdmin: BOOL; stdcall; external 'shell32.dll' name 'IsUserAnAdmin';

function CreateEnvironmentBlock(var lpEnvironment: Pointer; hToken: THandle;
                                    bInherit: BOOL): BOOL;
                                    stdcall; external 'Userenv.dll';

function DestroyEnvironmentBlock(pEnvironment: Pointer): BOOL; stdcall; external 'Userenv.dll';


function _GetIntegrityLevel() : DWORD;
type
    PTokenMandatoryLabel = ^TTokenMandatoryLabel;
    TTokenMandatoryLabel = packed record
    Label_ : TSidAndAttributes;
  end;
var
   hToken : THandle;
   cbSize: DWORD;
   pTIL : PTokenMandatoryLabel;
   dwTokenUserLength: DWORD;
begin
    Result := 0;
    dwTokenUserLength := MAXCHAR;
    if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, hToken) then begin
        pTIL := Pointer(LocalAlloc(0, dwTokenUserLength));
        if pTIL = nil then Exit;
        cbSize := SizeOf(TTokenMandatoryLabel);
        if GetTokenInformation(hToken, TokenIntegrityLevel,
                                    pTIL, dwTokenUserLength, cbSize) then
        if IsValidSid( (pTIL.Label_).Sid ) then
          Result := GetSidSubAuthority((pTIL.Label_).Sid, GetSidSubAuthorityCount((pTIL.Label_).Sid )^ - 1)^;
        if hToken <> INVALID_HANDLE_VALUE then
        CloseHandle(hToken);
        LocalFree(Cardinal(pTIL));
    end;
end;

function IsUserAnSystem(): Boolean;
const
     SECURITY_MANDATORY_SYSTEM_RID = $00004000;
begin
     Result := (_GetIntegrityLevel = SECURITY_MANDATORY_SYSTEM_RID);
end;

function StartTheService(Service:TService): Boolean;
var
   SCM: SC_HANDLE;
   ServiceHandle: SC_HANDLE;
begin
    Result:= False;
    SCM:= OpenSCManager(nil, nil, SC_MANAGER_ALL_ACCESS);
    if (SCM <> 0) then
    begin
        try
            ServiceHandle:= OpenService(SCM, PChar(Service.Name), SERVICE_ALL_ACCESS);
            if (ServiceHandle <> 0) then
            begin
                Result := StartService(ServiceHandle, 0, pChar(nil^));
                CloseServiceHandle(ServiceHandle);
            end;
        finally
            CloseServiceHandle(SCM);
        end;
    end;
end;

procedure SetServiceName(Service: TService);
begin
     if Assigned(Service) then begin
        Service.DisplayName := 'Run as system service created ' + DateTimeToStr(Now);
        Service.Name        := 'RunAsSystem' + FormatDateTime('ddmmyyyyhhnnss', Now);
     end;
end;

procedure CreateProcessAsSystem(const lpApplicationName: PWideChar;
                              const lpCommandLine:PWideChar = nil;
                              const lpCurrentDirectory: PWideChar  = nil);
begin
    if not ( IsUserAnAdmin ) then begin
       SetLastError(ERROR_ACCESS_DENIED);
       Exit();
    end;

    if not ( FileExists(lpApplicationName) ) then begin
       SetLastError(ERROR_FILE_NOT_FOUND);
       Exit();
    end;

    if ( IsUserAnSystem ) then
    begin
         SvcMgr.Application.Initialize;
         SvcMgr.Application.CreateForm(TsSysAccount, sSysAccount);
         sSysAccount.lpApplicationName  := lpApplicationName;
         sSysAccount.lpCommandLine      := lpCommandLine;
         sSysAccount.lpCurrentDirectory := lpCurrentDirectory;
         SetServiceName(sSysAccount);
         SvcMgr.Application.Run;
    end
    else begin
        SvcMgr.Application.Free;
        SvcMgr.Application := TServiceApplicationEx.Create(nil);
        SvcMgr.Application.Initialize;
        SvcMgr.Application.CreateForm(TsSysAccount, sSysAccount);
        SetServiceName(sSysAccount);
        SvcMgr.Application.ServicesRegister(True, True);
        try
           StartTheService(sSysAccount);
        finally
           SvcMgr.Application.ServicesRegister(False, True);
        end;
    end;
end;

procedure TServiceApplicationHelper.ServicesRegister(Install, Silent: Boolean);
begin
     RegisterServices(Install, Silent);
end;

procedure ServiceController(CtrlCode: DWord); stdcall;
begin
     sSysAccount.Controller(CtrlCode);
end;

function TsSysAccount.GetServiceController: TServiceController;
begin
     Result := ServiceController;
end;

Function ProcessIDFromAppname32( szExeFileName: String ): DWORD;
var
	Snapshot: THandle;
	ProcessEntry: TProcessEntry32;
Begin
	   Result := 0;
	   szExeFileName := UpperCase( szExeFileName );
	   Snapshot := CreateToolhelp32Snapshot(
				  TH32CS_SNAPPROCESS,
				  0 );
     If Snapshot <> 0 Then
	   try
	      ProcessEntry.dwSize := Sizeof( ProcessEntry );
	      If Process32First( Snapshot, ProcessEntry ) Then
	      Repeat
		          If Pos( szExeFileName,
                      UpperCase(ExtractFilename(
                      StrPas(ProcessEntry.szExeFile)))
                      ) > 0
		          then Begin
		               Result:= ProcessEntry.th32ProcessID;
                   Break;
		          end;
        until not Process32Next( Snapshot, ProcessEntry );
     finally
	          CloseHandle( Snapshot );
     end;
  End;

function TerminateProcessByID(ProcessID: Cardinal): Boolean;
var
   hProcess : THandle;
begin
     Result := False;
     hProcess := OpenProcess(PROCESS_TERMINATE,False,ProcessID);
     if hProcess > 0 then
     try
        Result := Win32Check(TerminateProcess(hProcess,0));
     finally
        CloseHandle(hProcess);
     end;
end;

procedure TsSysAccount.ServiceExecute(Sender: TService);
var
   hToken, hUserToken: THandle;
   StartupInfo : TStartupInfoW;
   ProcessInfo : TProcessInformation;
   P : Pointer;
begin
     if NOT WTSQueryUserToken(WtsGetActiveConsoleSessionID, hUserToken) then exit;

     if not OpenProcessToken(
                             OpenProcess(PROCESS_ALL_ACCESS, False,
                             ProcessIDFromAppname32('winlogon.exe'))
                             ,
                             MAXIMUM_ALLOWED,
                             hToken) then exit;

     if CreateEnvironmentBlock(P, hUserToken, True) then
     begin
          ZeroMemory(@StartupInfo, sizeof(StartupInfo));
          StartupInfo.lpDesktop := ('winsta0\default');
          StartupInfo.wShowWindow := SW_SHOWNORMAL;
          if CreateProcessAsUserW(
                hToken,
                lpApplicationName,
                lpCommandLine,
                nil,
                nil,
                False,
                CREATE_UNICODE_ENVIRONMENT,
                P,
                lpCurrentDirectory,
                StartupInfo,
                ProcessInfo) then
          begin

          end;
          CloseHandle(ProcessInfo.hProcess);
          CloseHandle(ProcessInfo.hThread);
          DestroyEnvironmentBlock(P);
     end;

     CloseHandle(hToken);
     CloseHandle(hUserToken);

     TerminateProcessByID(GetCurrentProcessId);
end;

end.
