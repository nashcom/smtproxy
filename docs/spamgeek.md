# Nash!Com SpamGeek

**SpamGeek** is a native Domino application which is based on an SMTP Extension Manager based on C-API.
It can modify headers and also intercept commands like a `XCLIENT` command and turn it into a `NOOP` operation after capturing XLCLIENT parameters and store them into separate log fields.

The application provides additional fields, which are not part of the official standard.



## Example formula

The following formula demonstrates the type of configuration.
In addition the configuration implementes the e-mail **address+tag@example.com** syntax.

```
@if (@begins(CurrentCommand; "XCLIENT");
@Do
(@SetField("xclient_String"; CurrentCommand);
 @SetField("xclient_RemoteHost"; @Left(@Right (CurrentCommand+" "; "NAME="); " "));
 @SetField("xclient_RemoteIP"; @Left (@Right (CurrentCommand+" "; "ADDR="); " "));
 @SetField("xclient_TLSVERSION"; @Left (@Right (CurrentCommand+" "; "TLSVERSION="); " "));
 @SetField("xclient_TLSCIPHER"; @Left (@Right (CurrentCommand+" "; "TLSCIPHER="); " "));
 @SetField("xclient_TLSCURVE"; @Left (@Right (CurrentCommand+" "; "TLSCURVE="); " "));
 @Return ("NOOP")
);
 @contains(CurrentCommand; "%"); @Return(@ReplaceSubstring (CurrentCommand; "%";"$")); "");
 CmdLower:=@Lowercase(CurrentCommand);
 @If (@Begins(CmdLower; "rcpt to"); ""; @Return (""));
 r:=@Right (CurrentCommand;":");x:=@Name([ADDRESS821];r);d:=@Right (x;"@"); e:=@Left(x;"@");
 @if (@contains(e;"+"); "RCPT TO:<" +@Left (e;"+")+"@"+d+">" ;"")
```

