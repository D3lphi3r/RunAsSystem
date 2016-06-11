program RunAsSys;

uses
  uSysAccount in 'uSysAccount.pas' {sSysAccount: TService};

{$R *.res}

begin
     CreateProcessAsSystem('C:\Windows\System32\cmd.exe');
end.


