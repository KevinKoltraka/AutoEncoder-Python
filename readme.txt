Ky kod është një sistem tërësor për detektimin e tentativave të login-it të dëmshme në një platformë online. Më poshtë, do të të shpjegoj çdo pjesë të kodit në mënyrë të thjeshtë dhe me shembuj konkretë për ta kuptuar më mirë.

1. Generimi i të dhënave (LoginDataGenerator)
Në këtë pjesë, po krijohet një dataset (të dhëna) që përdoret për të trajnuar modelin. Ky dataset është për logime të përdoruesve, ku disa mund të jenë të dëmshme dhe disa jo.

Ajo që bën kjo pjesë:
Krijon të dhëna të ndryshme për logimet e përdoruesve, si identifikuesi i përdoruesit (user_id), koha e login-it (login_time), suksesi i login-it (login_success), lloji i pajisjes dhe adresa IP.
Simulon logime të dëmshme: për shembull, për logimet që janë të dëmshme, ajo ndryshon koherencën e të dhënave, si kohën e login-it dhe suksesin e login-it.
Për shembull: Nëse një përdorues ka një IP që ndryshon herë pas here në mënyrë të çuditshme (si 10.0.42.187), mund të jetë një tentativë login-i e dëmshme.
python
Copy
Edit
sample_login = {
    'user_id': 6241,
    'login_time': 0.31,
    'login_success': 0,
    'device_type': 'unknown',
    'ip_address': '10.0.42.187',
    'geo_location': 'ASIA'
}
Ky është një shembull i një login-i që mund të jetë i dyshimtë: koha është shumë e shkurtër dhe lloji i pajisjes është "i panjohur". Përdoruesi gjithashtu ka një IP që vjen nga një vend tjetër, dhe kjo mund të duket e çuditshme.

2. Përpunimi i të Dhënave (LoginPreprocessor)
Pas krijimit të dataset-it, duhet të përpunohen këto të dhëna për t'i bërë ato të gatshme për trajnim.

Ajo që bën kjo pjesë:
Normalizimi i të dhënave numerike (si user_id, login_time, login_success) për t'i bërë ato më të krahasueshme mes tyre.
Shndërrimi i kolonave kategorike (si device_type, geo_location, ip_address) në forma numerike që mund të përdoren nga modelin. Përdoren teknika si OneHotEncoder për të përkthyer kategori si "mobile" në numra të kuptueshëm për modelin.
Për shembull:
Kategoria geo_location mund të ketë mundësi si US, EU, dhe ASIA. Me OneHotEncoder, kjo do të shndërrohet në dyshimet 0 ose 1, për shembull US mund të bëhet 1 0 0, EU bëhet 0 1 0, etj.
python
Copy
Edit
processed = self.ct.fit_transform(data)
Ky komandë përdor një transformues të kolonave për të përpunuar të dhënat.

3. Modeli i Detektimit të Kërcënimeve (ThreatDetectionModel)
Kjo është pjesa që ndihmon për të trajnuar një model që mund të parashikojë nëse një login është i dëmshëm apo jo.

Ajo që bën kjo pjesë:
Krijon një model të thellë të rrjetit neural (neural network), që përdor disa shtresa të ndryshme për të marrë vendime. Ky model merr të dhënat e përpunuara dhe bën parashikime mbi to.
Përdoret një funksion aktivizimi si "swish" që ndihmon që rrjeti të jetë më efikas.
Për shembull:
Modeli merr si input të dhënat që përpunohen, si për shembull login_time, device_type, dhe ip_address, dhe në fund parashikon nëse kjo është një tentativë malinje apo jo.
python
Copy
Edit
model = Sequential([
    Dense(128, activation='swish', input_shape=(input_dim,)),
    BatchNormalization(),
    Dropout(0.4),
    Dense(64, activation='swish'),
    Dropout(0.3),
    Dense(1, activation='sigmoid')
])
Ky është një shembull i një pjesë të modelit që është ndërtuar me disa shtresa për të trajnuar më mirë.

4. Monitorimi në Kohë Reale (ThreatMonitor)
Pas trajnimit të modelit, mund të përdorim këtë model për të analizuar çdo tentativë login-i që vjen në kohë reale dhe të përcaktojmë nëse është e dëmshme.

Ajo që bën kjo pjesë:
Përdor të modelin e trajnuar dhe procesin e përpunimit për të analizuar çdo login të ri dhe për të dhënë një vlerësim të rrezikut.
Për shembull:
Nëse një përdorues përpiqet të hyjë në sistem me një pajisje të panjohur dhe nga një IP që nuk është parë më parë, modelin mund të japë një verdict si MALICIOUS (e dëmshme).
python
Copy
Edit
result = monitor.analyze_login(sample_login)
print(result)
Ky është një shembull i përdorimit të sistemit të monitorimit në kohë reale. Ai analizon një login dhe jep një rezultat, si p.sh. MALICIOUS.

5. Vlerësimi i Modelit (full_evaluation)
Pas trajnimit, është e rëndësishme të vlerësojmë performancën e modelit për të parë sa mirë po punon.

Ajo që bën kjo pjesë:
Përdor raporte klasifikimi dhe matrica konfuzioni për të parë si ka performuar modeli në parashikimet e tij.
Gjithashtu, përdor kurba precision/recall për të gjetur pragun optimal të vendosjes së vendimit (kështu që mund të përmirësojmë saktësinë e modelit).
python
Copy
Edit
print(classification_report(y_test, y_class))
Ky komandë tregon se sa mirë performon modeli dhe nëse është e nevojshme të bëhen ndryshime.

Përmbledhje
Ky sistem është një mjet i fuqishëm për të mbrojtur sistemet nga tentativat e login-it të dëmshme, duke përdorur një proces të avancuar të përpunimit të të dhënave, modeleve të thella të detektimit të kërcënimeve, dhe monitorimit në kohë reale. Ai përdor të dhëna të simulura për të krijuar një model që mund të dallojë logimet e zakonshme nga ato të dyshuara dhe të ofrojë një analizë të menjëhershme për çdo tentativë hyrjeje.





user_id,login_time,login_success,device_type,ip_address,geo_location,is_malicious
4823,1.234,1,desktop,192.168.1.12,US,0
7391,0.456,0,unknown,10.0.32.18,ASIA,1
1548,1.789,1,mobile,172.16.0.45,EU,0
8921,0.312,0,unknown,10.0.47.29,OTHER,1
6374,2.145,1,tablet,192.168.1.78,US,0
2856,1.932,1,desktop,172.16.0.92,EU,0
9683,0.278,0,mobile,10.0.15.37,ASIA,1
4219,1.567,1,desktop,192.168.1.33,US,0
7041,0.189,0,unknown,10.0.8.42,OTHER,1
3562,1.876,1,mobile,172.16.0.11,EU,0
6241,0.31,0,unknown,10.0.42.187,ASIA,1
5837,1.456,1,tablet,192.168.1.65,US,0
9274,0.276,0,mobile,10.0.19.204,OTHER,1
1345,2.034,1,desktop,172.16.0.88,EU,0
7890,0.324,1,unknown,10.0.55.12,ASIA,1
4321,1.789,0,mobile,192.168.1.99,US,0
6578,0.198,0,desktop,10.0.33.45,ASIA,1
3245,1.923,1,tablet,172.16.0.73,EU,0
8790,0.287,0,unknown,10.0.22.66,OTHER,1
5432,1.654,1,mobile,192.168.1.44,US,0