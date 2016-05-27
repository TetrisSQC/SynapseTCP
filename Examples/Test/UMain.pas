unit UMain;

interface

uses
  System.SysUtils, System.Types, System.UITypes, System.Classes,
  System.Variants,
  FMX.Types, FMX.Controls, FMX.Forms, FMX.Graphics, FMX.Dialogs, FMX.StdCtrls,
  FMX.Edit, FMX.Controls.Presentation, FMX.ScrollBox, FMX.Memo;

type
  TfrmMain = class(TForm)
    tbTop: TToolBar;
    edUrl: TEdit;
    btnDownload: TButton;
    mmoDebug: TMemo;
    icImageControl: TImageControl;
    tbBottom: TToolBar;
    btnDate: TButton;
    edDate: TEdit;
    procedure btnDownloadClick(Sender: TObject);
    procedure btnDateClick(Sender: TObject);
  private
    { Private-Deklarationen }
  public
    { Public-Deklarationen }
    procedure HTTPCheck;
    procedure Log(const s: string);
  end;

var
  frmMain: TfrmMain;

implementation

uses
  blcksock,
  synsock,
  httpsend,
  sntpsend,
  ftpsend,
  pop3send;

{$R *.fmx}

procedure TfrmMain.btnDownloadClick(Sender: TObject);
begin
  HTTPCheck;
end;

procedure TfrmMain.btnDateClick(Sender: TObject);
var
  ntp: TSNtpSend;
begin
  ntp := TSNtpSend.Create;
  try
    ntp.TargetHost := 'pool.ntp.org';
    ntp.getsntp;
    edDate.Text := datetimeToStr(ntp.ntptime);
  finally
    ntp.Free;
  end;

end;

procedure TfrmMain.HTTPCheck;
var
  ls: TStringList;
  stream: TMemoryStream;
begin
  ls := TStringList.Create;
  stream := TMemoryStream.Create;
  try
    Log('Synapse from Delphi');
    HttpGetText(edUrl.Text, ls);
    Log(ls.Text);

    Log('Text size (expected 217, maybe crlf different): ' +
      IntToStr(Length(ls.Text)));

    HttpGetBinary('http://delphi.cz/img/Delphi_Certified_Dev.png', stream);

    Log('Stream size (expected 44 791): ' + IntToStr(stream.Size));
    stream.Position := 0;
    icImageControl.Bitmap.CreateFromStream(stream);

  finally
    ls.Free;
    stream.Free;
  end;
end;

procedure TfrmMain.Log(const s: string);
begin
  mmoDebug.Lines.Add(s);
end;

end.
