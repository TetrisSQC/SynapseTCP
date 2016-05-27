program Test;

uses
  System.StartUpCopy,
  FMX.Forms,
  UMain in 'UMain.pas' {frmMain},
  blcksock in '..\..\source\blcksock.pas',
  httpsend in '..\..\source\httpsend.pas',
  synabyte in '..\..\source\synabyte.pas',
  synacode in '..\..\source\synacode.pas',
  synafpc in '..\..\source\synafpc.pas',
  synaip in '..\..\source\synaip.pas',
  synautil in '..\..\source\synautil.pas',
  synsock in '..\..\source\synsock.pas',
  sntpsend in '..\..\source\sntpsend.pas',
  ftpsend in '..\..\source\ftpsend.pas',
  pop3send in '..\..\source\pop3send.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TfrmMain, frmMain);
  Application.Run;
end.
