{==============================================================================|
| Project : Ararat Synapse                                       | 003.012.008 |
|==============================================================================|
| Content: buffer wrapper layer
|==============================================================================|
| Copyright (c)1999-2014, Lukas Gebauer                                        |
| All rights reserved.                                                         |
|                                                                              |
| Redistribution and use in source and binary forms, with or without           |
| modification, are permitted provided that the following conditions are met:  |
|                                                                              |
| Redistributions of source code must retain the above copyright notice, this  |
| list of conditions and the following disclaimer.                             |
|                                                                              |
| Redistributions in binary form must reproduce the above copyright notice,    |
| this list of conditions and the following disclaimer in the documentation    |
| and/or other materials provided with the distribution.                       |
|                                                                              |
| Neither the name of Lukas Gebauer nor the names of its contributors may      |
| be used to endorse or promote products derived from this software without    |
| specific prior written permission.                                           |
|                                                                              |
| THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"  |
| AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE    |
| IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE   |
| ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR  |
| ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL       |
| DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR   |
| SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER   |
| CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT           |
| LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY    |
| OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH  |
| DAMAGE.                                                                      |
|==============================================================================|
| The Initial Developer of the Original Code is Lukas Gebauer (Czech Republic).|
| Portions created by Lukas Gebauer are Copyright (c) 1999-2012.               |
| All Rights Reserved.                                                         |
|==============================================================================|
| Contributor(s): Radek Cervinka, delphi.cz                                    |
|                 Ondrej Pokorny, kluug.net
|==============================================================================|
| History: see HISTORY.HTM from distribution package                           |
|          (Found at URL: http://www.ararat.cz/synapse/)                       |
|==============================================================================}

{:@abstract(NextGen and Unicode buffer layer)}


unit synabyte;

interface
uses
  sysutils;
{$IFDEF NEXTGEN}
    {$ZEROBASEDSTRINGS OFF}
{$ENDIF}
type
{$IFDEF UNICODE}
  TSynaByte = byte;
  TSynaBytes = record
  private
    FBytes: TBytes;
    FRefCheck: string;

    function GetChars(const Index: NativeInt): Char;
    procedure SetChars(const Index: NativeInt; const Value: Char);
    function AGetLength: NativeInt;
    procedure ASetLength(const Value: NativeInt);

    procedure UpdateTerminator;
    procedure CheckCow;
    procedure Unique;
  public
    class operator Implicit(const V1: String): TSynaBytes;
    class operator Implicit(const V1: TSynaBytes): String;
    class operator Implicit(const V1: Char): TSynaBytes;
    class operator Explicit(const V1: TBytes): TSynaBytes;


    class operator Add(const V1, V2: TSynaBytes): TSynaBytes;

    class operator Equal(const V1, V2: TSynaBytes): Boolean;
    class operator NotEqual(const V1, V2: TSynaBytes): Boolean;

    function Clone: TSynaBytes;
    procedure Delete(Start, Count: Integer);
    function Data: Pointer;


    property Chars[const Index: NativeInt]: Char read GetChars write SetChars; default;
    property Length: NativeInt read AGetLength write ASetLength;
    property Bytes:TBytes read FBytes;
  end;

//  procedure SetLength(var s: TSynaBytes; Count:Integer); overload;

{$ELSE}
  TSynaBytes = AnsiString;
  TSynaByte = AnsiChar;
{$ENDIF}

  function StringOf(const bytes: TSynaBytes):string; overload;
  function StringOf(const by: TBytes):string; overload;
  procedure DeleteInternal (var s: TSynaBytes; Start, Count: Integer);

implementation

{$IFDEF UNICODE}

function IsBytesEquals(const Bytes1, Bytes2: TBytes; const Len1, Len2: NativeInt): Boolean;
var
  i: NativeInt;
begin
  if Len1 <> Len2 then
    Exit(False);

  for i := 0 to Len1 - 1 do
    if Bytes1[i] <> Bytes2[i] then
      Exit(False);

  Result := True;
end;

class operator TSynaBytes.Implicit(const V1: String): TSynaBytes;
var
  I: Integer;
begin
  Result.Length := System.Length(V1);
  for I := 1 to System.Length(V1) do
    Result.FBytes[I-1] := Byte(V1[I]);//warning: null-terminated strings!
end;
 
class operator TSynaBytes.Add(const V1, V2: TSynaBytes): TSynaBytes;
begin
  Result.Length := V1.Length + V2.Length;
  if V1.Length > 0 then
    Move(V1.FBytes[0], Result.FBytes[0], V1.Length);
  if V2.Length > 0 then
    Move(V2.FBytes[0], Result.FBytes[V1.Length], V2.Length);
end;

procedure TSynaBytes.CheckCow;
  function RefCount: Integer;
  var
    xStrPtr: ^Integer;
  begin
    //get reference count of FStrBuffer, correct results on 32bit, 64bit and also mobile
    xStrPtr := Pointer(PChar(FRefCheck));
    Dec(xStrPtr, 2);
    Result := xStrPtr^;
  end;

begin
  if RefCount <> 1 then
  begin
    Unique;
  end;
  FRefCheck := '!';
end;

function TSynaBytes.Clone: TSynaBytes;
begin
  Result.Length := Self.Length;
  Move(FBytes[0], Result.FBytes[0], Self.Length);
end;

function TSynaBytes.Data: Pointer;
begin
  Result := @FBytes[0];
end;

// zero based
procedure TSynaBytes.Delete(Start, Count: Integer);
begin
  if Count <= 0 then
    Exit;
  CheckCow;
  if Length - Count <= 0 then
  begin
    Length := 0;
    Exit;
  end;
  if (Start >= 0) then
  begin
    Move(FBytes[Start + Count], FBytes[Start], Length - Count);
    Length := Length - Count;
  end;
end;

class operator TSynaBytes.Equal(const V1, V2: TSynaBytes): Boolean;
begin
  Result := IsBytesEquals(V1.FBytes, V2.FBytes, V1.Length, V2.Length);
end;

class operator TSynaBytes.Explicit(const V1: TBytes): TSynaBytes;
begin
  Result.Length := System.Length(V1);
  Move(V1[0], Result.FBytes[0], Result.Length);
end;

function TSynaBytes.GetChars(const Index: NativeInt): Char;
begin
  Result := Char(FBytes[Index]);
end;

function TSynaBytes.AGetLength: NativeInt;
begin
  Result := System.Length(FBytes);

  if Result > 0 then
    Result := Result - 1;  // Null Terminator
end;

class operator TSynaBytes.Implicit(const V1: Char): TSynaBytes;
begin
  Result.Length := 1;
  Result.FBytes[0] := Byte(V1);
end;

class operator TSynaBytes.Implicit(const V1: TSynaBytes): String;
var
  I: Integer;
  C: PWord;
begin
  SetLength(Result, V1.Length);
  if V1.Length > 0 then
  begin
    C := PWord(PWideChar(Result));
    for I := 0 to V1.Length-1 do
    begin
      C^ := V1.FBytes[I];
      Inc(C);
    end;
  end;
end;

class operator TSynaBytes.NotEqual(const V1, V2: TSynaBytes): Boolean;
begin
  Result := not IsBytesEquals(V1.FBytes, V2.FBytes, V1.Length, V2.Length);
end;

procedure TSynaBytes.SetChars(const Index: NativeInt; const Value: Char);
begin
  CheckCow;
  FBytes[Index] := Byte(Value);
end;

procedure TSynaBytes.Unique;
var
  b:TBytes;
begin
  SetLength(b, Self.Length + 1);
  Move(FBytes[0], b[0], Self.Length);
  FBytes := b;
end;

procedure TSynaBytes.UpdateTerminator;
begin
  if System.Length(FBytes) > 0 then
    FBytes[System.Length(FBytes) - 1] := 0;
end;

procedure TSynaBytes.ASetLength(const Value: NativeInt);
begin
  System.SetLength(FBytes, Value + 1); // +1, null terminator
  Self.UpdateTerminator();
end;
{$ENDIF}

function StringOf(const bytes: TSynaBytes):string;
begin
  Result := bytes;
end;

function StringOf(const by: TBytes):string;
var
  I: Integer;
  C: PWord;
begin
  SetLength(Result, Length(by));
  if Length(by) > 0 then
  begin
    C := PWord(PWideChar(Result));
    for I := 0 to Length(by)-1 do
    begin
      C^ := by[I];
      Inc(C);
    end;
  end;
end;
procedure DeleteInternal (var s: TSynaBytes; Start, Count: Integer);
begin
{$IFDEF UNICODE}
  s.Delete(Start - 1, Count);
{$ELSE}
  Delete(s, Start , Count);
{$ENDIF}
end;
     
end.
