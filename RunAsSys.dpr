program RunAsSys;

uses
  uSysAccount in 'uSysAccount.pas' {sSysAccount: TService};


begin
     CreateProcessAsSystem( 'c:\windows\system32\cmd.exe');
end.


