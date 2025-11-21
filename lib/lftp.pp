{ lFTP

  CopyRight (C) 2005-2008 Ales Katona
  feature/lFTP-MDTM-MFMT CopyRight (C) 2020-2024 Pavel Mokry

  This library is Free software; you can rediStribute it and/or modify it
  under the terms of the GNU Library General Public License as published by
  the Free Software Foundation; either version 2 of the License, or (at your
  option) any later version.

  This program is diStributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; withOut even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE. See the GNU Library General Public License
  for more details.

  You should have received a Copy of the GNU Library General Public License
  along with This library; if not, Write to the Free Software Foundation,
  Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

  This license has been modified. See File LICENSE for more inFormation.
  Should you find these sources withOut a LICENSE File, please contact
  me at ales@chello.sk
}

unit lFTP;

{$mode objfpc}{$H+}
{$inline on}
{$macro on}
{$define debug}

interface

uses
  Classes, lNet, lTelnet;

const
  DEFAULT_FTP_PORT = 1025;

type
  TLFTP = class;
  TLFTPClient = class;

  TLFTPStatus = (
    fsNone{0}, fsCon{1}, fsUser{2}, fsPass{3}, fsPasv{4},
    fsPort{5}, fsList{6}, fsRetr{7}, fsStor{8}, fsType{9},
    fsCWD{10}, fsMKD{11}, fsRMD{12}, fsDEL{13}, fsRNFR{14},
    fsRNTO{15}, fsSYS{16}, fsFeat{17}, fsPWD{18}, fsHelp{19},
    fsQuit{20}, fsLast{21}, fsMlsd{22}, fsMlst{23}, fsMfmt{24},
    fsMdtm{25});

  TLFTPStatusSet = set of TLFTPStatus;

  TLFTPStatusRec = record
    Status: TLFTPStatus;
    Args: array[1..2] of string;
  end;

  TLFTPTransferMethod = (ftActive, ftPassive);

  TLFTPClientStatusEvent = procedure(aSocket: TLSocket;
    const aStatus: TLFTPStatus) of object;

  { TLFTPStatusStack }

  { TLFTPStatusFront }
  {$DEFINE __front_type__  :=  TLFTPStatusRec}
  {$i lcontainersh.inc}
  TLFTPStatusFront = TLFront;

  TLFTP = class(TLComponent, ILDirect)
  protected
    FControl: TLTelnetClient;
    FData: TLTcp;//TLTcpList;
    FSending: boolean;
    FTransferMethod: TLFTPTransferMethod;
    FFeatureList: TStringList;
    FFeatureString: string;

    function GetConnected: boolean; virtual;

    function GetTimeout: integer;
    procedure SetTimeout(const Value: integer);

    function GetSession: TLSession;
    procedure SetSession(const AValue: TLSession);
    procedure SetCreator(AValue: TLComponent); override;

    function GetSocketClass: TLSocketClass;
    procedure SetSocketClass(Value: TLSocketClass);
  public
    constructor Create(aOwner: TComponent); override;
    destructor Destroy; override;

    function Get(out aData; const aSize: integer; aSocket: TLSocket = nil): integer;
      virtual; abstract;
    function GetMessage(out msg: string; aSocket: TLSocket = nil): integer;
      virtual; abstract;

    function Send(const aData; const aSize: integer; aSocket: TLSocket = nil): integer;
      virtual; abstract;
    function SendMessage(const msg: string; aSocket: TLSocket = nil): integer;
      virtual; abstract;
  public
    property Connected: boolean read GetConnected;
    property Timeout: integer read GetTimeout write SetTimeout;
    property SocketClass: TLSocketClass read GetSocketClass write SetSocketClass;
    property ControlConnection: TLTelnetClient read FControl;
    property DataConnection: TLTCP read FData;
    property TransferMethod: TLFTPTransferMethod
      read FTransferMethod write FTransferMethod default ftPassive;
    property Session: TLSession read GetSession write SetSession;
    property FeatureList: TStringList read FFeatureList;
  end;

  { TLFTPTelnetClient }

  TLFTPTelnetClient = class(TLTelnetClient)
  protected
    procedure React(const Operation, Command: char); override;
  end;

  { TLFTPClient }

  TLFTPClient = class(TLFTP, ILClient)
  protected
    FStatus: TLFTPStatusFront;
    FCommandFront: TLFTPStatusFront;
    FStoreFile: TFileStream;
    FExpectedBinary: boolean;
    FPipeLine: boolean;
    FPassword: string;
    FPWD: string;
    FParsedData: string;
    FStatusFlags: array[TLFTPStatus] of boolean;

    FOnError: TLSocketErrorEvent;
    FOnReceive: TLSocketEvent;
    FOnSent: TLSocketProgressEvent;
    FOnControl: TLSocketEvent;
    FOnConnect: TLSocketEvent;
    FOnSuccess: TLFTPClientStatusEvent;
    FOnFailure: TLFTPClientStatusEvent;

    FChunkSize: word;
    FLastPort: word;
    FStartPort: word;
    FStatusSet: TLFTPStatusSet;
    FSL: TStringList; // for evaluation, I want to prevent constant create/free
    procedure OnRe(aSocket: TLSocket);
    procedure OnDs(aSocket: TLSocket);
    procedure OnSe(aSocket: TLSocket);
    procedure OnEr(const msg: string; aSocket: TLSocket);

    procedure OnControlEr(const msg: string; aSocket: TLSocket);
    procedure OnControlRe(aSocket: TLSocket);
    procedure OnControlCo(aSocket: TLSocket);
    procedure OnControlDs(aSocket: TLSocket);
    procedure OnDataConnect(aSocket: TLSocket);

    procedure StopSending;

    procedure ClearStatusFlags;

    function GetCurrentStatus: TLFTPStatus;
    function GetTransfer: boolean;

    function GetEcho: boolean;
    procedure SetEcho(const Value: boolean);

    procedure ParsePWD(const s: string);

    function GetConnected: boolean; override;

    function GetBinary: boolean;
    procedure SetBinary(const Value: boolean);

    function CanContinue(const aStatus: TLFTPStatus; const Arg1, Arg2: string): boolean;

    function CleanInput(var s: string): integer;

    procedure SetStartPor(const Value: word);

    procedure EvaluateFeatures;
    procedure EvaluateAnswer(const Ans: string);

    procedure PasvPort;

    function User(const aUserName: string): boolean;
    function Password(const aPassword: string): boolean;

    procedure SendChunk(const Event: boolean);

    procedure ExecuteFrontCommand;
  public
    constructor Create(aOwner: TComponent); override;
    destructor Destroy; override;

    function Get(out aData; const aSize: integer; aSocket: TLSocket = nil): integer;
      override;
    function GetMessage(out msg: string; aSocket: TLSocket = nil): integer; override;

    function Send(const aData; const aSize: integer; aSocket: TLSocket = nil): integer;
      override;
    function SendMessage(const msg: string; aSocket: TLSocket = nil): integer; override;

    function Connect(const aHost: string; const aPort: word = 21): boolean;
      virtual; overload;
    function Connect: boolean; virtual; overload;

    function Authenticate(const aUsername, aPassword: string): boolean;

    function GetData(out aData; const aSize: integer): integer;
    function GetDataMessage: string;

    function Retrieve(const FileName: string): boolean;
    function Put(const FileName: string): boolean; virtual; // because of LCLsocket

    function ChangeDirectory(const DestPath: string): boolean;
    function MakeDirectory(const DirName: string): boolean;
    function RemoveDirectory(const DirName: string): boolean;

    function DeleteFile(const FileName: string): boolean;
    function Rename(const FromName, ToName: string): boolean;

    function GetFileModifiedTime(const AFileName: string): boolean;

    function ModifyFileModifiedTime(const AFileName: string;
      YYYMMDDHHMMSS: string): boolean; overload;
    function ModifyFileModifiedTime(const AFileName: string;
      Year, Month, Day, Hour, Minute, Second: word): boolean; overload;
    function ModifyFileModifiedTime(const AFileName: string;
      AFileModifiedDateTime: TDateTime): boolean; overload;
  public
    procedure List(const FileName: string = '');
    procedure Nlst(const FileName: string = '');

    procedure Mlsd(const FileName: string = '');
    procedure Mlst(const FileName: string = '');

    procedure SystemInfo;
    procedure ListFeatures;
    procedure PresentWorkingDirectory;
    procedure Help(const Arg: string);
    // Kiewitz
    procedure Quit;

    procedure Disconnect(const Forced: boolean = False); override;

    procedure CallAction; override;
  public
    property StatusSet: TLFTPStatusSet read FStatusSet write FStatusSet;
    property ChunkSize: word read FChunkSize write FChunkSize;
    property Binary: boolean read GetBinary write SetBinary;
    property PipeLine: boolean read FPipeLine write FPipeLine;
    property Echo: boolean read GetEcho write SetEcho;
    property StartPort: word read FStartPort write FStartPort default DEFAULT_FTP_PORT;
    property Transfer: boolean read GetTransfer;
    property CurrentStatus: TLFTPStatus read GetCurrentStatus;
    property PresentWorkingDirectoryString: string read FPWD;
    property ParsedData: string read FParsedData;


    property OnError: TLSocketErrorEvent read FOnError write FOnError;
    property OnConnect: TLSocketEvent read FOnConnect write FOnConnect;
    property OnSent: TLSocketProgressEvent read FOnSent write FOnSent;
    property OnReceive: TLSocketEvent read FOnReceive write FOnReceive;
    property OnControl: TLSocketEvent read FOnControl write FOnControl;
    property OnSuccess: TLFTPClientStatusEvent read FOnSuccess write FOnSuccess;
    property OnFailure: TLFTPClientStatusEvent read FOnFailure write FOnFailure;
  end;

function FTPStatusToStr(const aStatus: TLFTPStatus): string;

{$ifdef debug}

type
  TDebugLogProc = procedure(msg: string) of object;

const
  LNetDebugLogProc: TDebugLogProc = nil;

  {$endif}


implementation

uses
  SysUtils, Math;

const
  FLE = #13#10;

  EMPTY_REC: TLFTPStatusRec = (Status: fsNone; Args: ('', ''));

  FTPStatusStr: array[TLFTPStatus] of string =
    ('None', 'Connect', 'Authenticate', 'Password',
    'Passive', 'Active', 'List', 'Retrieve',
    'Store', 'Type', 'CWD', 'MKDIR',
    'RMDIR', 'Delete', 'RenameFrom',
    'RenameTo', 'System', 'Features',
    'PWD', 'HELP', 'QUIT', 'LAST', 'MLSD',
    'MLST', 'MFMT', 'MDTM');

procedure Writedbg(const ar: array of const);
{$ifdef debug}
var
  i: integer;
  s: string;
begin
  if assigned(LNetDebugLogProc) then
  begin
    s := 'lFTP.Writedbg: ';
    if High(ar) >= 0 then
      for i := 0 to High(ar) do
        case ar[i].vtype of
          vtInteger:   s := Format('%s%d', [s, ar[i].vinteger]);
          vtInt64:     s := Format('%s%d', [s, ar[i].vInt64^]);
          vtString:    s := Format('%s%s', [s, ar[i].vstring^]);
          vtAnsiString:s := Format('%s%s', [s, ansistring(ar[i].vpointer)]);
          vtBoolean:   s := Format('%s%d', [s, ord(ar[i].vboolean)]);
          vtChar:      s := Format('%s%s', [s, ar[i].vchar]);
          vtExtended:  s := Format('%s%x', [s, Int64(ar[i].vpointer)]);
        end;
		LNetDebugLogProc(s);
  end
  else
  begin
    if High(ar) >= 0 then
      for i := 0 to High(ar) do
        case ar[i].vtype of
          vtInteger: Write(ar[i].vinteger);
          vtString: Write(ar[i].vstring^);
          vtAnsiString: Write(ansistring(ar[i].vpointer));
          vtBoolean: Write(ar[i].vboolean);
          vtChar: Write(ar[i].vchar);
          vtExtended: Write(extended(ar[i].vpointer^));
        end;
    Writeln;
  end;
end;
{$else}
begin
end;
{$endif}

function MakeStatusRec(const aStatus: TLFTPStatus;
  const Arg1, Arg2: string): TLFTPStatusRec;
begin
  Result.Status := aStatus;
  Result.Args[1] := Arg1;
  Result.Args[2] := Arg2;
end;

function FTPStatusToStr(const aStatus: TLFTPStatus): string;
begin
  Result := FTPStatusStr[aStatus];
end;

{$i lcontainers.inc}

{ TLFTP }

function TLFTP.GetSession: TLSession;
begin
  Result := FControl.Session;
end;

procedure TLFTP.SetSession(const AValue: TLSession);
begin
  FControl.Session := aValue;
  FData.Session := aValue;
end;

procedure TLFTP.SetCreator(AValue: TLComponent);
begin
  inherited SetCreator(AValue);

  FControl.Creator := AValue;
  FData.Creator := AValue;
end;

function TLFTP.GetConnected: boolean;
begin
  Result := FControl.Connected;
end;

function TLFTP.GetTimeout: integer;
begin
  Result := FControl.Timeout;
end;

procedure TLFTP.SetTimeout(const Value: integer);
begin
  FControl.Timeout := Value;
  FData.Timeout := Value;
end;

function TLFTP.GetSocketClass: TLSocketClass;
begin
  Result := FControl.SocketClass;
end;

procedure TLFTP.SetSocketClass(Value: TLSocketClass);
begin
  FControl.SocketClass := Value;
  FData.SocketClass := Value;
end;

constructor TLFTP.Create(aOwner: TComponent);
begin
  inherited Create(aOwner);

  FHost := '';
  FPort := 21;

  FControl := TLFTPTelnetClient.Create(nil);
  FControl.Creator := Self;

  FData := TLTcp.Create(nil);
  FData.Creator := Self;
  FData.SocketClass := TLSocket;

  FTransferMethod := ftPassive; // let's be modern

  FFeatureList := TStringList.Create;
end;

destructor TLFTP.Destroy;
begin
  FControl.Free;
  FData.Free;
  FFeatureList.Free;

  inherited Destroy;
end;

{ TLFTPTelnetClient }

procedure TLFTPTelnetClient.React(const Operation, Command: char);
begin
  // don't do a FUCK since they broke Telnet in FTP as per-usual
end;

{ TLFTPClient }

constructor TLFTPClient.Create(aOwner: TComponent);
const
  DEFAULT_CHUNK = 8192;
begin
  inherited Create(aOwner);

  FControl.OnReceive := @OnControlRe;
  FControl.OnConnect := @OnControlCo;
  FControl.OnError := @OnControlEr;
  FControl.OnDisconnect := @OnControlDs;

  FData.OnReceive := @OnRe;
  FData.OnDisconnect := @OnDs;
  FData.OnCanSend := @OnSe;
  FData.OnError := @OnEr;
  FData.OnConnect   := @OnDataConnect;

  FStatusSet := [fsNone..fsLast]; // full Event set
  FPassWord := '';
  FChunkSize := DEFAULT_CHUNK;
  FStartPort := DEFAULT_FTP_PORT;
  FSL := TStringList.Create;
  FLastPort := FStartPort;

  ClearStatusFlags;

  FStatus := TLFTPStatusFront.Create(EMPTY_REC);
  FCommandFront := TLFTPStatusFront.Create(EMPTY_REC);

  FStoreFile := nil;
end;

destructor TLFTPClient.Destroy;
begin
  Disconnect(True);
  FSL.Free;
  FStatus.Free;
  FCommandFront.Free;
  if Assigned(FStoreFile) then
    FreeAndNil(FStoreFile);
  inherited Destroy;
end;

procedure TLFTPClient.OnRe(aSocket: TLSocket);
begin
  Writedbg(['OnRe(Data): data received, Connected=', FData.Connected]);
  if Assigned(FOnReceive) then
    FOnReceive(aSocket);
end;

procedure TLFTPClient.OnDs(aSocket: TLSocket);
begin
  Writedbg(['OnDs(Data): Disconnected, FSending=', FSending]);
  StopSending;
end;

procedure TLFTPClient.OnSe(aSocket: TLSocket);
begin
  Writedbg(['OnSe(Data): CanSend, Connected=', Connected, ', FSending=', FSending]);
  if Connected and FSending then
    SendChunk(True);
end;

procedure TLFTPClient.OnEr(const msg: string; aSocket: TLSocket);
begin
  Writedbg(['OnEr(Data): ', msg, ', FSending=', FSending]);
  StopSending;
  if Assigned(FOnError) then
    FOnError(msg, aSocket);
end;

procedure TLFTPClient.OnControlEr(const msg: string; aSocket: TLSocket);
begin
  StopSending;

  if Assigned(FOnFailure) then
  begin
    while not FStatus.Empty do
      FOnFailure(aSocket, FStatus.Remove.Status);
  end
  else
    FStatus.Clear;

  ClearStatusFlags;

  if Assigned(FOnError) then
    FOnError(msg, aSocket);
end;

procedure TLFTPClient.OnControlRe(aSocket: TLSocket);
begin
  if Assigned(FOnControl) then
    FOnControl(aSocket);
end;

procedure TLFTPClient.OnControlCo(aSocket: TLSocket);
begin
  if Assigned(FOnConnect) then
    FOnConnect(aSocket);
end;

procedure TLFTPClient.OnControlDs(aSocket: TLSocket);
begin
  StopSending;

  if Assigned(FOnError) then
    FOnError('Connection lost', aSocket);
end;

procedure TLFTPClient.OnDataConnect(aSocket: TLSocket);
begin
  Writedbg(['OnCo(Data): Connected=', FData.Connected,
            ', Local=', FData.Iterator.LocalAddress, ':', FData.Iterator.LocalPort,
            ', Remote=', FData.Iterator.PeerAddress, ':', FData.Iterator.PeerPort,
            ', FSending=', FSending]);

  // If an upload is pending, kick off sending now
  if FSending and Assigned(FStoreFile) then
    SendChunk(True);
end;

procedure TLFTPClient.StopSending;
begin
  FSending := False;

  if Assigned(FStoreFile) then
    FreeAndNil(FStoreFile);
end;

procedure TLFTPClient.ClearStatusFlags;
var
  s: TLFTPStatus;
begin
  for s := fsNone to fsLast do
    FStatusFlags[s] := False;
end;

function TLFTPClient.GetCurrentStatus: TLFTPStatus;
begin
  Result := FStatus.First.Status;
end;

function TLFTPClient.GetTransfer: boolean;
begin
  Result := FData.Connected;
end;

function TLFTPClient.GetEcho: boolean;
begin
  Result := FControl.OptionIsSet(TS_ECHO);
end;

function TLFTPClient.GetConnected: boolean;
begin
  Result := FStatusFlags[fsCon] and inherited;
end;

function TLFTPClient.GetBinary: boolean;
begin
  Result := FStatusFlags[fsType];
end;

function TLFTPClient.CanContinue(const aStatus: TLFTPStatus;
  const Arg1, Arg2: string): boolean;
begin
  Result := FPipeLine or FStatus.Empty;
  if not Result then
    FCommandFront.Insert(MakeStatusRec(aStatus, Arg1, Arg2));
end;

function TLFTPClient.CleanInput(var s: string): integer;
var
  i: integer;
begin
  FSL.Text := s;
  for i := 0 to FSL.Count - 1 do
    if Length(FSL[i]) > 0 then
      EvaluateAnswer(FSL[i]);

  s := StringReplace(s, FLE, LineEnding, [rfReplaceAll]);
  i := Pos('PASS', s);
  if i > 0 then
    s := Copy(s, 1, i - 1) + 'PASS';
  Result := Length(s);
end;

procedure TLFTPClient.SetStartPor(const Value: word);
begin
  FStartPort := Value;
  if Value > FLastPort then
    FLastPort := Value;
end;

procedure TLFTPClient.EvaluateFeatures;
var
  i: integer;
begin
  FFeatureList.Clear;
  if Length(FFeatureString) = 0 then
    Exit;

  FFeatureList.Text := FFeatureString;
  FFeatureString := '';
  FFeatureList.Delete(0);

  i := 0;
  while i < FFeatureList.Count do
  begin
    if (Length(Trim(FFeatureList[i])) = 0) or (FFeatureList[i][1] <> ' ') then
    begin
      FFeatureList.Delete(i);
      Continue;
    end;

    FFeatureList[i] := Trim(FFeatureList[i]);

    Inc(i);
  end;
end;

procedure TLFTPClient.SetEcho(const Value: boolean);
begin
  if Value then
    FControl.SetOption(TS_ECHO)
  else
    FControl.UnSetOption(TS_ECHO);
end;

procedure TLFTPClient.ParsePWD(const s: string);
var
  i: integer;
  IsIn: boolean = False;
begin
  FPWD := '';
  for i := 1 to Length(s) do
  begin
    if s[i] = '"' then
    begin
      IsIn := not IsIn;
      Continue;
    end;
    if IsIn then
      FPWD := FPWD + s[i];
  end;
end;

procedure TLFTPClient.SetBinary(const Value: boolean);
const
  TypeBool: array[boolean] of string = ('A', 'I');
begin
  if CanContinue(fsType, BoolToStr(Value), '') then
  begin
    FExpectedBinary := Value;
    FStatus.Insert(MakeStatusRec(fsType, '', ''));
    FControl.SendMessage('TYPE ' + TypeBool[Value] + FLE);
  end;
end;

procedure TLFTPClient.EvaluateAnswer(const Ans: string);

  function GetNum: integer;
  begin
    Result := -1;
    if (Length(Ans) >= 3) and (Ans[1] in ['0'..'9']) and
      (Ans[2] in ['0'..'9']) and (Ans[3] in ['0'..'9']) then
      Result := StrToInt(Copy(Ans, 1, 3));
  end;

  (*
  procedure ParsePortIP(s: string);
  var
    i, l: integer;
    aIP: string;
    aPort: word;
    sl: TStringList;
  begin
    if Length(s) >= 15 then
    begin
      sl := TStringList.Create;
      for i := Length(s) downto 5 do
        if s[i] = ',' then Break;
      while (i <= Length(s)) and (s[i] in ['0'..'9', ',']) do Inc(i);
      if not (s[i] in ['0'..'9', ',']) then Dec(i);
      l := 0;
      while s[i] in ['0'..'9', ','] do
      begin
        Inc(l);
        Dec(i);
      end;
      Inc(i);
      s := Copy(s, i, l);
      sl.CommaText := s;
      aIP := sl[0] + '.' + sl[1] + '.' + sl[2] + '.' + sl[3];
      try
        aPort := (StrToInt(sl[4]) * 256) + StrToInt(sl[5]);
      except
        aPort := 0;
      end;
      Writedbg(['Server PASV addr/port - ', aIP, ' : ', aPort]);
      if (aPort > 0) and FData.Connect(aIP, aPort) then
      begin
        Writedbg(['Connected after PASV']);
        // Short delay for Windows CE, had aborted connection errors w/o it
        //Sleep(50);
      end;
      sl.Free;
      FStatus.Remove;
    end;
  end;
  *)

  procedure ParsePortIP(s: string);
  var
    i, startParen, endParen: integer;
    inner: string;
    sl: TStringList;
    aIP: string;
    aPort: word;
  begin
    // Find '('
    startParen := Pos('(', s);
    if startParen = 0 then
      Exit; // malformed reply

    // Find last ')', scanning from the end (manual RPos for one char)
    endParen := 0;
    for i := Length(s) downto startParen + 1 do
      if s[i] = ')' then
      begin
        endParen := i;
        Break;
      end;

    if (endParen = 0) or (endParen <= startParen + 1) then
      Exit; // malformed reply

    // Extract the stuff inside parentheses: "h1,h2,h3,h4,p1,p2"
    inner := Copy(s, startParen + 1, endParen - startParen - 1);

    sl := TStringList.Create;
    try
      sl.StrictDelimiter := True;
      sl.Delimiter := ',';      // we only want to split on commas
      sl.DelimitedText := inner;

      if sl.Count < 6 then
        Exit; // not enough parts

      aIP :=
        sl[0] + '.' + sl[1] + '.' + sl[2] + '.' + sl[3];

      // Use StrToIntDef just in case
      aPort :=
        word(StrToIntDef(sl[4], 0) * 256 + StrToIntDef(sl[5], 0));

      Writedbg(['PASV raw response = "', s, '"']);
      Writedbg(['Server PASV addr/port - ', aIP, ' : ', aPort]);

      if (aPort > 0) and FData.Connect(aIP, aPort) then
      begin
        Writedbg(['Connected after PASV',
                  ', Data.Connected=', FData.Connected,
                  ', Local=', FData.Iterator.LocalAddress,
                  ':', FData.Iterator.LocalPort,
                  ', Remote=', FData.Iterator.PeerAddress,
                  ':', FData.Iterator.PeerPort]);
        // Sleep(50);
      end
      else
      begin
        Writedbg(['FAILED to connect after PASV to ', aIP, ':', aPort]);
      end;

      FStatus.Remove;
    finally
      sl.Free;
    end;
  end;

  (*
  procedure SendFile;
  begin
    FStoreFile.Position := 0;
    FSending := True;
    SendChunk(False);
  end;
  *)
  procedure SendFile;
  begin
    if not Assigned(FStoreFile) then
    begin
      Writedbg(['SendFile: FStoreFile=nil – nothing to send']);
      Exit;
    end;

    FStoreFile.Position := 0;
    FSending := True;

    Writedbg(['SendFile: starting upload of "', FStatus.First.Args[1],
              '", size=', FStoreFile.Size,
              ', ChunkSize=', FChunkSize,
              ', Data.Connected=', FData.Connected]);

    if FData.Connected then
    begin
      Writedbg(['SendFile: data socket already connected – doing initial SendChunk']);
      SendChunk(False);
    end
    else
    begin
      Writedbg(['SendFile: data socket NOT yet connected – waiting for OnDataConnect']);
      // OnDataConnect will call SendChunk(True) when the connect event fires
    end;
  end;

  function ValidResponse(const Answer: string): boolean; inline;
  begin
    Result := (Length(Ans) >= 3) and (Ans[1] in ['1'..'5']) and
      (Ans[2] in ['0'..'9']) and (Ans[3] in ['0'..'9']);

    if Result then
      Result := (Length(Ans) = 3) or ((Length(Ans) > 3) and (Ans[4] = ' '));
  end;

  procedure Eventize(const aStatus: TLFTPStatus; const Res: boolean);
  begin
    FStatus.Remove;
    if Res then
    begin
      if Assigned(FOnSuccess) and (aStatus in FStatusSet) then
        FOnSuccess(FData.Iterator, aStatus);
    end
    else
    begin
      if Assigned(FOnFailure) and (aStatus in FStatusSet) then
        FOnFailure(FData.Iterator, aStatus);
    end;
  end;

var
  x: integer;
begin
  x := GetNum;
  Writedbg(['WOULD EVAL: ', FTPStatusStr[FStatus.First.Status],
    ' with value: ', x, ' from "', Ans, '"']);

  case FStatus.First.Status of
    fsFeat:
    begin
      FFeatureString := FFeatureString + Ans + FLE; // we need to parse this later
    end;
    fsMlst:
    begin
      if x < 0 then
      begin
        FParsedData := Ans;
      end;
    end;
  end;


  if ValidResponse(Ans) then
    if not FStatus.Empty then
    begin
      Writedbg(['EVAL: ', FTPStatusStr[FStatus.First.Status], ' with value: ', x]);
      case FStatus.First.Status of
        fsCon: case x of
            220:
            begin
              FStatusFlags[FStatus.First.Status] := True;
              Eventize(FStatus.First.Status, True);
            end;
            else
            begin
              FStatusFlags[FStatus.First.Status] := False;
              Eventize(FStatus.First.Status, False);
            end;
          end;

        fsUser: case x of
            230:
            begin
              FStatusFlags[FStatus.First.Status] := True;
              Eventize(FStatus.First.Status, True);
            end;
            331,
            332:
            begin
              FStatus.Remove;
              Password(FPassword);
            end;
            else
            begin
              FStatusFlags[FStatus.First.Status] := False;
              Eventize(FStatus.First.Status, False);
            end;
          end;

        fsPass: case x of
            230:
            begin
              FStatusFlags[FStatus.First.Status] := True;
              Eventize(FStatus.First.Status, True);
            end;
            else
            begin
              FStatusFlags[FStatus.First.Status] := False;
              Eventize(FStatus.First.Status, False);
            end;
          end;

        fsPasv: case x of
            227: ParsePortIP(Ans);
            300..600: FStatus.Remove;
          end;

        fsPort: case x of
            200:
            begin
              Eventize(FStatus.First.Status, True);
            end;
            else
            begin
              Eventize(FStatus.First.Status, False);
            end;
          end;

        fsType: case x of
            200:
            begin
              FStatusFlags[FStatus.First.Status] := FExpectedBinary;
              Writedbg(['Binary mode: ', FExpectedBinary]);
              Eventize(FStatus.First.Status, True);
            end;
            else
            begin
              Eventize(FStatus.First.Status, False);
            end;
          end;

        fsRetr: case x of
            125, 150: begin { Do nothing }
              end;
          end;


            fsStor: case x of
              125, 150:
              begin
                Writedbg(['fsStor: got ', x,
                          ' (', Ans, '), FStoreFile assigned=',
                          Assigned(FStoreFile),
                          ', FSending=', FSending]);
                if Assigned(FStoreFile) then
                  SendFile
                else
                begin
                  Writedbg(['fsStor: got 125/150 but FStoreFile=nil, marking STOR as failed']);
                  Eventize(FStatus.First.Status, False);
                end;
              end;

              226:
              begin
                Writedbg(['fsStor: got 226 (transfer complete)']);
                Eventize(FStatus.First.Status, True);
              end;

              else
              begin
                Writedbg(['fsStor: got unexpected code ', x, ' – treating as failure']);
                Eventize(FStatus.First.Status, False);
              end;
            end;

        fsCWD: case x of
            200, 250:
            begin
              FStatusFlags[FStatus.First.Status] := True;
              Eventize(FStatus.First.Status, True);
            end;
            else
            begin
              FStatusFlags[FStatus.First.Status] := False;
              Eventize(FStatus.First.Status, False);
            end;
          end;

        fsPWD: case x of
            257:
            begin
              ParsePWD(Ans);
              FStatusFlags[FStatus.First.Status] := True;
              Eventize(FStatus.First.Status, True);
            end;
            else
            begin
              FStatusFlags[FStatus.First.Status] := False;
              Eventize(FStatus.First.Status, False);
            end;
          end;

        fsHelp: case x of
            211, 214:
            begin
              FStatusFlags[FStatus.First.Status] := True;
              Eventize(FStatus.First.Status, True);
            end;
            else
            begin
              FStatusFlags[FStatus.First.Status] := False;
              Eventize(FStatus.First.Status, False);
            end;
          end;

        fsList: case x of
            125, 150: begin { do nothing }
            end;
            226:
            begin
              Eventize(FStatus.First.Status, True);
            end;
            else
            begin
              Eventize(FStatus.First.Status, False);
            end;
          end;

        fsMKD: case x of
            250, 257:
            begin
              FStatusFlags[FStatus.First.Status] := True;
              Eventize(FStatus.First.Status, True);
            end;
            else
            begin
              FStatusFlags[FStatus.First.Status] := False;
              Eventize(FStatus.First.Status, False);
            end;
          end;

        fsRMD,
        fsDEL: case x of
            250:
            begin
              FStatusFlags[FStatus.First.Status] := True;
              Eventize(FStatus.First.Status, True);
            end;
            else
            begin
              FStatusFlags[FStatus.First.Status] := False;
              Eventize(FStatus.First.Status, False);
            end;
          end;

        fsRNFR: case x of
            350:
            begin
              FStatusFlags[FStatus.First.Status] := True;
              Eventize(FStatus.First.Status, True);
            end;
            else
            begin
              Eventize(FStatus.First.Status, False);
            end;
          end;

        fsRNTO: case x of
            250:
            begin
              FStatusFlags[FStatus.First.Status] := True;
              Eventize(FStatus.First.Status, True);
            end;
            else
            begin
              Eventize(FStatus.First.Status, False);
            end;
          end;
        fsFeat: case x of
            200..299:
            begin
              FStatusFlags[FStatus.First.Status] := True;
              EvaluateFeatures;
              Eventize(FStatus.First.Status, True);
            end;
            else
            begin
              FFeatureString := '';
              Eventize(FStatus.First.Status, False);
            end;
          end;
        fsQUIT: case x of
            221:
            begin
              FStatusFlags[FStatus.First.Status] := True;
              Eventize(FStatus.First.Status, True);
            end;
            else
            begin
              Eventize(FStatus.First.Status, False);
            end;
          end;

        fsMlsd: case x of
            125, 150: begin { do nothing }
            end;
            226:
            begin
              Eventize(FStatus.First.Status, True);
            end;
            else
            begin
              Eventize(FStatus.First.Status, False);
            end;
          end;
        fsMlst: case x of
            -1, 125, 150: begin { do nothing }
            end;
            250:
            begin
              if Ans[4] = '-' then
              begin
                FParsedData := '';
              end;
              if Ans[4] = ' ' then
              begin
                Eventize(FStatus.First.Status, True);
              end;
            end;
            else
            begin
              Eventize(FStatus.First.Status, False);
            end;
          end;
        fsMfmt: case x of
            213, 253:
            begin
              Eventize(FStatus.First.Status, True);
            end;
            else
            begin
              Eventize(FStatus.First.Status, False);
            end;
          end;

        fsMdtm: case x of
            213:
            begin
              FParsedData := copy(Ans, 5, length(Ans) - 4);
              Eventize(FStatus.First.Status, True);
            end;
            else
            begin
              Eventize(FStatus.First.Status, False);
            end;
          end;

      end;
    end;
  if FStatus.Empty and not FCommandFront.Empty then
    ExecuteFrontCommand;
end;

procedure TLFTPClient.PasvPort;

  function StringPair(const aPort: word): string;
  begin
    Result := IntToStr(aPort div 256);
    Result := Result + ',' + IntToStr(aPort mod 256);
  end;

  function StringIP: string;
  begin
    Result := StringReplace(FControl.Connection.Iterator.LocalAddress,
      '.', ',', [rfReplaceAll]) + ',';
  end;

begin
  if FTransferMethod = ftActive then
  begin
    Writedbg(['Sent PORT']);
    FData.Disconnect(True);
    FData.Listen(FLastPort);
    FStatus.Insert(MakeStatusRec(fsPort, '', ''));
    FControl.SendMessage('PORT ' + StringIP + StringPair(FLastPort) + FLE);

    if FLastPort < 65535 then
      Inc(FLastPort)
    else
      FLastPort := FStartPort;
  end
  else
  begin
    Writedbg(['Sent PASV']);
    FStatus.Insert(MakeStatusRec(fsPasv, '', ''));
    FControl.SendMessage('PASV' + FLE);
  end;
end;

function TLFTPClient.User(const aUserName: string): boolean;
begin
  Result := not FPipeLine;
  if CanContinue(fsUser, aUserName, '') then
  begin
    FStatus.Insert(MakeStatusRec(fsUser, '', ''));
    FControl.SendMessage('USER ' + aUserName + FLE);
    Result := True;
  end;
end;

function TLFTPClient.Password(const aPassword: string): boolean;
begin
  Result := not FPipeLine;
  if CanContinue(fsPass, aPassword, '') then
  begin
    FStatus.Insert(MakeStatusRec(fsPass, '', ''));
    FControl.SendMessage('PASS ' + aPassword + FLE);
    Result := True;
  end;
end;

(*
procedure TLFTPClient.SendChunk(const Event: boolean);
var
  Buf: array[0..65535] of byte;
  n: integer;
  Sent: integer;
begin
  // Nothing to do if we don't have a file anymore
  if not Assigned(FStoreFile) then
    Exit;

  repeat
    // In case StopSending was called between iterations
    if (not Assigned(FStoreFile)) or (not FSending) then
      Exit;

    n := FStoreFile.Read(Buf, FChunkSize);
    if n > 0 then
    begin
      Sent := FData.Send(Buf, n);

      // FData.Send may synchronously trigger OnEr/OnDs → StopSending
      if (not Assigned(FStoreFile)) or (not FSending) then
        Exit;

      if Event and Assigned(FOnSent) and (Sent > 0) then
        FOnSent(FData.Iterator, Sent);

      // User's OnSent handler could also call StopSending
      if (not Assigned(FStoreFile)) or (not FSending) then
        Exit;

      if Sent < n then
        FStoreFile.Position := FStoreFile.Position - (n - Sent);
    end
    else
    begin
      if Assigned(FOnSent) then
        FOnSent(FData.Iterator, 0);
      StopSending;
      FData.Disconnect(False);
    end;
  until (n = 0) or (Sent = 0);
end;
*)
procedure TLFTPClient.SendChunk(const Event: boolean);
var
  Buf: array[0..65535] of byte;
  n: integer;
  Sent: integer;
begin
  if not Assigned(FStoreFile) then
  begin
    Writedbg(['SendChunk: FStoreFile=nil – aborting']);
    Exit;
  end;

  repeat
    if (not Assigned(FStoreFile)) or (not FSending) then
    begin
      Writedbg(['SendChunk: aborted, FSending=', FSending,
                ', FStoreFile assigned=', Assigned(FStoreFile)]);
      Exit;
    end;

    n := FStoreFile.Read(Buf, FChunkSize);
    Writedbg(['SendChunk: read n=', n, ' bytes, pos=', FStoreFile.Position]);

    if n > 0 then
    begin
      Sent := FData.Send(Buf, n);
      Writedbg(['SendChunk: FData.Send requested=', n,
                ', sent=', Sent,
                ', Data.Connected=', FData.Connected]);

      if (not Assigned(FStoreFile)) or (not FSending) then
      begin
        Writedbg(['SendChunk: aborted after Send, FSending=', FSending]);
        Exit;
      end;

      if Event and Assigned(FOnSent) and (Sent > 0) then
        FOnSent(FData.Iterator, Sent);

      if (not Assigned(FStoreFile)) or (not FSending) then
      begin
        Writedbg(['SendChunk: aborted after FOnSent, FSending=', FSending]);
        Exit;
      end;

      if Sent < n then
      begin
        FStoreFile.Position := FStoreFile.Position - (n - Sent);
        Writedbg(['SendChunk: partial send, rewinding to position ',
                  FStoreFile.Position]);
      end;
    end
    else
    begin
      Writedbg(['SendChunk: EOF reached, closing data connection']);
      if Assigned(FOnSent) then
        FOnSent(FData.Iterator, 0);
      StopSending;
      FData.Disconnect(False);
    end;
  until (n = 0) or (Sent = 0);
end;

procedure TLFTPClient.ExecuteFrontCommand;
begin
  with FCommandFront.First do
    case Status of
      fsNone: Exit;
      fsUser: User(Args[1]);
      fsPass: Password(Args[1]);
      fsList: List(Args[1]);
      fsRetr: Retrieve(Args[1]);
      fsStor: Put(Args[1]);
      fsCWD: ChangeDirectory(Args[1]);
      fsMKD: MakeDirectory(Args[1]);
      fsRMD: RemoveDirectory(Args[1]);
      fsDEL: DeleteFile(Args[1]);
      fsRNFR: Rename(Args[1], Args[2]);
      fsSYS: SystemInfo;
      fsPWD: PresentWorkingDirectory;
      fsHelp: Help(Args[1]);
      fsType: SetBinary(StrToBool(Args[1]));
      fsFeat: ListFeatures;
      fsMlsd: Mlsd(Args[1]);
      fsMlst: Mlst(Args[1]);
      fsMdtm: GetFileModifiedTime(Args[1]);
    end;
  FCommandFront.Remove;
end;

function TLFTPClient.Get(out aData; const aSize: integer; aSocket: TLSocket): integer;
var
  s: string;
begin
  Result := FControl.Get(aData, aSize, aSocket);
  if Result > 0 then
  begin
    SetLength(s, Result);
    Move(aData, PChar(s)^, Result);
    Result := CleanInput(s);
    Move(s[1], aData, Min(Length(s), aSize));
  end;
end;

function TLFTPClient.GetMessage(out msg: string; aSocket: TLSocket): integer;
begin
  Result := FControl.GetMessage(msg, aSocket);
  if Result > 0 then
    Result := CleanInput(msg);
end;

function TLFTPClient.Send(const aData; const aSize: integer;
  aSocket: TLSocket): integer;
begin
  Result := FControl.Send(aData, aSize);
end;

function TLFTPClient.SendMessage(const msg: string; aSocket: TLSocket): integer;
begin
  Result := FControl.SendMessage(msg);
end;

function TLFTPClient.GetData(out aData; const aSize: integer): integer;
begin
  Result := FData.Iterator.Get(aData, aSize);
end;

function TLFTPClient.GetDataMessage: string;
begin
  Result := '';
  if Assigned(FData.Iterator) then
    FData.Iterator.GetMessage(Result);
end;

function TLFTPClient.Connect(const aHost: string; const aPort: word): boolean;
begin
  Result := False;
  Disconnect(True);
  if FControl.Connect(aHost, aPort) then
  begin
    FHost := aHost;
    FPort := aPort;
    FStatus.Insert(MakeStatusRec(fsCon, '', ''));
    Result := True;
  end;
  if FData.Eventer <> FControl.Connection.Eventer then
    FData.Eventer := FControl.Connection.Eventer;
end;

function TLFTPClient.Connect: boolean;
begin
  Result := Connect(FHost, FPort);
end;

function TLFTPClient.Authenticate(const aUsername, aPassword: string): boolean;
begin
  FPassword := aPassWord;
  Result := User(aUserName);
end;

function TLFTPClient.Retrieve(const FileName: string): boolean;
begin
  Result := not FPipeLine;
  if CanContinue(fsRetr, FileName, '') then
  begin
    PasvPort;
    FStatus.Insert(MakeStatusRec(fsRetr, '', ''));
    FControl.SendMessage('RETR ' + FileName + FLE);
    Result := True;
  end;
end;

(*
function TLFTPClient.Put(const FileName: string): boolean;
begin
  Result := not FPipeLine;
  if FileExists(FileName) and CanContinue(fsStor, FileName, '') then
  begin
    FStoreFile := TFileStream.Create(FileName, fmOpenRead);
    PasvPort;
    FStatus.Insert(MakeStatusRec(fsStor, '', ''));
    FControl.SendMessage('STOR ' + ExtractFileName(FileName) + FLE);
    Result := True;
  end;
end;
*)
function TLFTPClient.Put(const FileName: string): boolean;
begin
  Result := not FPipeLine;
  if FileExists(FileName) and CanContinue(fsStor, FileName, '') then
  begin
    Writedbg(['Put: preparing upload of "', FileName, '"']);
    FStoreFile := TFileStream.Create(FileName, fmOpenRead);
    Writedbg(['Put: FStoreFile.Size=', FStoreFile.Size]);

    PasvPort;
    FStatus.Insert(MakeStatusRec(fsStor, FileName, ''));
    FControl.SendMessage('STOR ' + ExtractFileName(FileName) + FLE);
    Result := True;
  end
  else
  begin
    if not FileExists(FileName) then
      Writedbg(['Put: File does not exist: ', FileName])
    else
      Writedbg(['Put: Cannot continue (pipeline busy) for ', FileName]);
  end;
end;

function TLFTPClient.ChangeDirectory(const DestPath: string): boolean;
begin
  Result := not FPipeLine;
  if CanContinue(fsCWD, DestPath, '') then
  begin
    FStatus.Insert(MakeStatusRec(fsCWD, '', ''));
    FStatusFlags[fsCWD] := False;
    FControl.SendMessage('CWD ' + DestPath + FLE);
    Result := True;
  end;
end;

function TLFTPClient.MakeDirectory(const DirName: string): boolean;
begin
  Result := not FPipeLine;
  if CanContinue(fsMKD, DirName, '') then
  begin
    FStatus.Insert(MakeStatusRec(fsMKD, '', ''));
    FStatusFlags[fsMKD] := False;
    FControl.SendMessage('MKD ' + DirName + FLE);
    Result := True;
  end;
end;

function TLFTPClient.RemoveDirectory(const DirName: string): boolean;
begin
  Result := not FPipeLine;
  if CanContinue(fsRMD, DirName, '') then
  begin
    FStatus.Insert(MakeStatusRec(fsRMD, '', ''));
    FStatusFlags[fsRMD] := False;
    FControl.SendMessage('RMD ' + DirName + FLE);
    Result := True;
  end;
end;

function TLFTPClient.DeleteFile(const FileName: string): boolean;
begin
  Result := not FPipeLine;
  if CanContinue(fsDEL, FileName, '') then
  begin
    FStatus.Insert(MakeStatusRec(fsDEL, '', ''));
    FControl.SendMessage('DELE ' + FileName + FLE);
    Result := True;
  end;
end;

function TLFTPClient.Rename(const FromName, ToName: string): boolean;
begin
  Result := not FPipeLine;
  if CanContinue(fsRNFR, FromName, ToName) then
  begin
    FStatus.Insert(MakeStatusRec(fsRNFR, '', ''));
    FStatusFlags[fsRNFR] := False;
    FControl.SendMessage('RNFR ' + FromName + FLE);

    FStatus.Insert(MakeStatusRec(fsRNTO, '', ''));
    FStatusFlags[fsRNTO] := False;
    FControl.SendMessage('RNTO ' + ToName + FLE);

    Result := True;
  end;
end;

function TLFTPClient.GetFileModifiedTime(const AFileName: string): boolean;
begin
  Result := not FPipeLine;
  if CanContinue(fsMdtm, AFileName, '') and (FFeatureList.IndexOf('MDTM') >= 0) then
  begin
    FStatus.Insert(MakeStatusRec(fsMdtm, '', ''));
    FStatusFlags[fsMdtm] := False;
    FControl.SendMessage('MDTM ' + AFileName + FLE);
    Result := True;
  end;
end;

function TLFTPClient.ModifyFileModifiedTime(const AFileName: string;
  YYYMMDDHHMMSS: string): boolean; overload;
begin
  Result := not FPipeLine;
  if CanContinue(fsMfmt, AFileName, YYYMMDDHHMMSS) and
    (FFeatureList.IndexOf('MFMT') >= 0) then
  begin
    FStatus.Insert(MakeStatusRec(fsMfmt, '', ''));
    FControl.SendMessage('MFMT ' + YYYMMDDHHMMSS + ' ' + AFileName + FLE);
    Result := True;
  end;
end;


function TLFTPClient.ModifyFileModifiedTime(const AFileName: string;
  Year, Month, Day, Hour, Minute, Second: word): boolean;
var
  sDateTime: string;
begin
  Result := not FPipeLine;
  sDateTime := Format('%.4d%.2d%.2d%.2d%.2d%.2d', [Year, Month, Day,
    Hour, Minute, Second]);
  Result := ModifyFileModifiedTime(AFileName, sDateTime);
end;

function TLFTPClient.ModifyFileModifiedTime(const AFileName: string;
  AFileModifiedDateTime: TDateTime): boolean;
var
  Year, Month, Day, Hour, Minute, Second, MilliSecond: word;
begin
  DecodeDate(AFileModifiedDateTime, Year, Month, Day);
  DecodeTime(AFileModifiedDateTime, Hour, Minute, Second, MilliSecond);
  Result := ModifyFileModifiedTime(AFileName, Year, Month, Day, Hour, Minute, Second);
end;

procedure TLFTPClient.List(const FileName: string = '');
begin
  if CanContinue(fsList, FileName, '') then
  begin
    PasvPort;
    FStatus.Insert(MakeStatusRec(fsList, '', ''));
    if Length(FileName) > 0 then
      FControl.SendMessage('LIST ' + FileName + FLE)
    else
      FControl.SendMessage('LIST' + FLE);
  end;
end;

procedure TLFTPClient.Nlst(const FileName: string);
begin
  if CanContinue(fsList, FileName, '') then
  begin
    PasvPort;
    FStatus.Insert(MakeStatusRec(fsList, '', ''));
    if Length(FileName) > 0 then
      FControl.SendMessage('NLST ' + FileName + FLE)
    else
      FControl.SendMessage('NLST' + FLE);
  end;
end;

procedure TLFTPClient.Mlsd(const FileName: string = '');
begin
  if CanContinue(fsMlsd, FileName, '') then
  begin
    PasvPort;
    FStatus.Insert(MakeStatusRec(fsMlsd, '', ''));
    if Length(FileName) > 0 then
      FControl.SendMessage('MLSD ' + FileName + FLE)
    else
      FControl.SendMessage('MLSD' + FLE);
  end;
end;

procedure TLFTPClient.Mlst(const FileName: string = '');
begin
  if CanContinue(fsMlst, FileName, '') then
  begin
    FStatus.Insert(MakeStatusRec(fsMlst, '', ''));
    FStatusFlags[fsMlst] := False;
    FControl.SendMessage('MLST ' + FileName + FLE);
  end;
end;

procedure TLFTPClient.SystemInfo;
begin
  if CanContinue(fsSYS, '', '') then
    FControl.SendMessage('SYST' + FLE);
end;

procedure TLFTPClient.ListFeatures;
begin
  if CanContinue(fsFeat, '', '') then
  begin
    FStatus.Insert(MakeStatusRec(fsFeat, '', ''));
    FControl.SendMessage('FEAT' + FLE);
  end;
end;

procedure TLFTPClient.PresentWorkingDirectory;
begin
  if CanContinue(fsPWD, '', '') then
  begin
    FStatus.Insert(MakeStatusRec(fsPWD, '', ''));
    FControl.SendMessage('PWD' + FLE);
  end;
end;

procedure TLFTPClient.Help(const Arg: string);
begin
  if CanContinue(fsHelp, Arg, '') then
  begin
    FStatus.Insert(MakeStatusRec(fsHelp, Arg, ''));
    FControl.SendMessage('HELP ' + Arg + FLE);
  end;
end;

procedure TLFTPClient.Quit;
begin
  if CanContinue(fsQuit, '', '') then
  begin
    FStatus.Insert(MakeStatusRec(fsQuit, '', ''));
    FControl.SendMessage('QUIT' + FLE);
  end;
end;

procedure TLFTPClient.Disconnect(const Forced: boolean = False);
begin
  FControl.Disconnect(Forced);
  FStatus.Clear;
  FData.Disconnect(Forced);
  FLastPort := FStartPort;
  ClearStatusFlags;
  FCommandFront.Clear;
end;

procedure TLFTPClient.CallAction;
begin
  TLFTPTelnetClient(FControl).CallAction;
end;

initialization
  Randomize;

end.
