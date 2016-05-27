{$H+}
{$IFDEF WIN32}
{$IFNDEF MSWINDOWS}
{$DEFINE MSWINDOWS}
{$ENDIF}
{$ENDIF}
unit rtspsend;

interface

uses
  SysUtils, Classes,
  blcksock, synautil, synaip, synacode, synsock;

const
  cRTSPProtocol = '554';

type
  TRTSPSend = class(TSynaClient)
  private
    FConnectionTimeOut: Integer;
    FCSeq: Integer;
    FPublicOptions: String;
    FRTSPTimeOut: Integer;
    FServer: String;
    FSession: String;
    FStreamID: string;
    FTransport: string;
  protected
    FSock: TTCPBlockSocket;
    FHeaders: TStringList;
    FDocument: TMemoryStream;
    FResultCode: Integer;
    FResultString: string;
    FUserAgent: string;
    FUploadSize: Integer;
    function ReadUnknown: Boolean;
    function ReadIdentity(Size: Integer): Boolean;
    function PrepareHeaders: String;
    function InternalDoConnect: Boolean;
    function InternalConnect: Boolean;
  public
    constructor Create;
    destructor Destroy; override;

    { :Reset headers and document and Mimetype. }
    procedure Clear;

    { :Decode ResultCode and ResultString from Value. }
    procedure DecodeStatus(const Value: string);

    { :Connects to host define in URL and access to resource defined in URL by
     method. If Document is not empty, send it to server as part of HTTP request.
     Server response is in Document and headers. Connection may be authorised
     by username and password in URL. If you define proxy properties, connection
     is made by this proxy. If all OK, result is @true, else result is @false.

     If you use in URL 'https:' instead only 'http:', then your request is made
     by SSL/TLS connection (if you not specify port, then port 443 is used
     instead standard port 80). If you use SSL/TLS request and you have defined
     HTTP proxy, then HTTP-tunnel mode is automaticly used . }
    function RTSPMethod(const Method, URL: string; cSeq: Integer = -1): Boolean;

    { :You can call this method from OnStatus event for break current data
     transfer. (or from another thread.) }
    procedure Abort;

    property ConnectionTimeOut: Integer read FConnectionTimeOut
      write FConnectionTimeOut;
    property cSeq: Integer read FCSeq write FCSeq;
    { :Before HTTP operation you may define any non-standard headers for HTTP
     request, except of: 'Expect: 100-continue', 'Content-Length', 'Content-Type',
     'Connection', 'Authorization', 'Proxy-Authorization' and 'Host' headers.
     After HTTP operation contains full headers of returned document. }
    property Headers: TStringList read FHeaders;

    { :Stream with document to send (before request, or with document received
     from HTTP server (after request). }
    property Document: TMemoryStream read FDocument;
    property PublicOptions: String read FPublicOptions;

    { :Here you can specify custom User-Agent indentification. By default is
     used: 'Mozilla/4.0 (compatible; Synapse)' }
    property UserAgent: string read FUserAgent write FUserAgent;

    { :After successful @link(RTSPMethod) method contains result code of
     operation. }
    property ResultCode: Integer read FResultCode;

    { :After successful @link(RTSPMethod) method contains string after result code. }
    property ResultString: string read FResultString;
    property RTSPTimeOut: Integer read FRTSPTimeOut write FRTSPTimeOut;
    property Server: String read FServer;
    property Session: String read FSession write FSession;

    { :if this value is not 0, then data upload pending. In this case you have
     here total sice of uploaded data. It is good for draw upload progressbar
     from OnStatus event. }
    property UploadSize: Integer read FUploadSize;
    { :Socket object used for TCP/IP operation. Good for seting OnStatus hook, etc. }
    property Sock: TTCPBlockSocket read FSock;
    property StreamID: string read FStreamID write FStreamID;
    property Transport: string read FTransport;

  end;

implementation

constructor TRTSPSend.Create;
begin
  inherited Create;
  FHeaders := TStringList.Create;
  FDocument := TMemoryStream.Create;
  FSock := TTCPBlockSocket.Create;
  FSock.Owner := self;
  FSock.ConvertLineEnd := True;
  FSock.SizeRecvBuffer := c64k;
  FSock.SizeSendBuffer := c64k;
  FTimeout := 20000;
  FConnectionTimeOut := 0;
  FTargetPort := cRTSPProtocol;
  FUserAgent := '';
  FUploadSize := 0;
  Clear;
end;

destructor TRTSPSend.Destroy;
begin
  FSock.Free;
  if assigned(FDocument) then
    FDocument.Free;
  FHeaders.Free;
  inherited Destroy;
end;

procedure TRTSPSend.Clear;
begin
  if assigned(FDocument) then
    FDocument.Clear;
  FHeaders.Clear;
end;

procedure TRTSPSend.DecodeStatus(const Value: string);
var
  s, su: string;
begin
  s := Trim(SeparateRight(Value, ' '));
  su := Trim(SeparateLeft(s, ' '));
  FResultCode := StrToIntDef(su, 0);
  FResultString := Trim(SeparateRight(s, ' '));
  if FResultString = s then
    FResultString := '';
end;

function TRTSPSend.PrepareHeaders: String;
begin
  Result := string({$IFDEF UNICODE}TMarshal.AsAnsi{$ENDIF}(AdjustLineBreaks(FHeaders.Text, tlbsCRLF)));
end;

function TRTSPSend.InternalDoConnect: Boolean;
begin
  Result := False;
  FSock.CloseSocket;
  FSock.Bind(FIPInterface, cAnyPort);
  FSock.ConnectionTimeOut := FConnectionTimeOut;
  if FSock.LastError <> 0 then
    Exit;
  FSock.Connect(FTargetHost, FTargetPort);
  if FSock.LastError <> 0 then
    Exit;
  Result := True;
end;

function TRTSPSend.InternalConnect: Boolean;
begin
  if FSock.Socket = INVALID_SOCKET then
    Result := InternalDoConnect
  else if FSock.CanRead(0) then
    Result := InternalDoConnect
  else
    Result := True;
end;

function TRTSPSend.RTSPMethod(const Method, URL: string;
  cSeq: Integer = -1): Boolean;
var
  Sending, Receiving: Boolean;
  Size: Integer;
  Prot, User, Pass, Host, Port, Path, Para, URI: string;
  s: String;
  l: TStringList;
  x: Integer;
  u, c: Integer;
begin
  { initial values }
  Result := False;
  FResultCode := 500;
  FResultString := '';
  FUploadSize := 0;
  FPublicOptions := '';
  if cSeq = -1 then
    Inc(FCSeq)
  else
    FCSeq := cSeq;
  URI := ParseURL(URL, Prot, User, Pass, Host, Port, Path, Para);
  try
    Sending := FDocument.Size > 0;
  { Headers for Sending data }
    if Sending then
    begin
      FHeaders.Insert(0, 'Content-Length: ' + IntToStr(FDocument.Size));
    end;
  { setting User-agent }
    if FUserAgent <> '' then
      FHeaders.Insert(0, 'User-Agent: ' + FUserAgent);

    if URI = '/*' then
      URI := '*';
    if FSession <> '' then
      FHeaders.Insert(0, 'Session: ' + FSession);
    if FCSeq > 0 then
      FHeaders.Insert(0, 'CSeq: ' + IntToStr(FCSeq));

    FHeaders.Insert(0, UpperCase(Method) + ' ' + URL + ' RTSP/1.0');

    FTargetHost := Host;
    FTargetPort := Port;
    if FHeaders[FHeaders.Count - 1] <> '' then
      FHeaders.Add('');

  { connect }
    if not InternalConnect then
    begin
      Exit;
    end;

  { reading Status }
    FDocument.Position := 0;

  { upload content }
    if Sending then
    begin
      if FDocument.Size >= c64k then
      begin
        FSock.SendString(PrepareHeaders);
        FUploadSize := FDocument.Size;
        FSock.SendBuffer(FDocument.Memory, FDocument.Size);
      end
      else
      begin
        s := PrepareHeaders + ReadStrFromStream(FDocument, FDocument.Size);
        FUploadSize := Length(s);
        FSock.SendString(s);
      end;
    end
    else
    begin
    { we not need to upload document, send headers only }
      FSock.SendString(PrepareHeaders);
    end;

    if FSock.LastError <> 0 then
      Exit;

    Clear;
    Size := -1;

    repeat
      repeat
        s := FSock.RecvString(FTimeout);
        if s <> '' then
          Break;
      until FSock.LastError <> 0;
      if Pos('RTSP/', UpperCase(s)) = 1 then
      begin
        FHeaders.Add(s);
        DecodeStatus(s);
      end
      else
      begin
      { old HTTP 0.9 and some buggy servers not send result }
        s := s + CRLF;
        WriteStrToStream(FDocument, s);
        FResultCode := 0;
      end;
    until (FSock.LastError <> 0) or (FResultCode <> 100);

  { if need receive headers, receive and parse it }
    if FHeaders.Count > 0 then
    begin
      l := TStringList.Create;
      try
        repeat
          s := FSock.RecvString(FTimeout);
          l.Add(s);
          if s = '' then
            Break;
        until FSock.LastError <> 0;
        x := 0;
        while l.Count > x do
        begin
          s := NormalizeHeader(l, x);
          FHeaders.Add(s);
          u := Pos(':', s);
          if u > 0 then
          begin
            repeat
              Inc(u);
            until (u > Length(s)) or (Copy(s, u, 1) <> ' ');
            if (CompareString('CSeq:', s)) then
            begin
              FCSeq := StrToIntDef(Copy(s, u, Length(s)), 0);
            end
            else if (CompareString('Session:', s)) then
            begin
              c := Pos(';timeout=', s);
              if c > 0 then
              begin
                FRTSPTimeOut := StrToIntDef(Copy(s, u + 9, Length(s)), 10);
                Delete(s, c, Length(s));
              end;
              FSession := Copy(s, u, Length(s))
            end
            else if (CompareString('Public:', s)) then
            begin
              FPublicOptions := Copy(s, u, Length(s))
            end
            else if (CompareString('Content-Length:', s)) then
            begin
              Size := StrToIntDef(Copy(s, u, Length(s)), -1);
            end
            else if (CompareString('com.ses.streamID:', s)) then
            begin
              FStreamID := Copy(s, u, Length(s));
            end
            else if (CompareString('Transport:', s)) then
            begin
              FTransport := Copy(s, u, Length(s));
            end
            else if (CompareString('Server:', s)) then
            begin
              FServer := Copy(s, u, Length(s));
            end
          end;
        end;
      finally
        l.Free;
      end;
    end;

    Result := FSock.LastError = 0;
    if not Result then
      Exit;

  { if need receive response body, read it }
    Receiving := (FResultCode <> 204);
    Receiving := Receiving and (FResultCode <> 304);
    if Receiving and (Size > 0) then
      Result := ReadIdentity(Size);

    FDocument.Position := 0;
  except
    FSock.CloseSocket;
  end;
end;

function TRTSPSend.ReadUnknown: Boolean;
var
  s: string;
begin
  Result := False;
  repeat
    s := FSock.RecvPacket(FTimeout);
    if FSock.LastError = 0 then
      WriteStrToStream(FDocument, s);
  until FSock.LastError <> 0;
  if FSock.LastError = WSAECONNRESET then
  begin
    Result := True;
    FSock.ResetLastError;
  end;
end;

function TRTSPSend.ReadIdentity(Size: Integer): Boolean;
begin
  if Size > 0 then
  begin
    FSock.RecvStreamSize(FDocument, FTimeout, Size);
    FDocument.Position := FDocument.Size;
    Result := FSock.LastError = 0;
  end
  else
    Result := True;
end;

procedure TRTSPSend.Abort;
begin
  FSock.StopFlag := True;
end;

end.
