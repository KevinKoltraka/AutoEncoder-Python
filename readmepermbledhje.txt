
Ky projekt përdor Deep Learning për të rritur sigurinë në Cloud Security, duke analizuar hyrjet në sistem dhe zbuluar sjelljet e dyshimta. Ja si funksionon në mënyrë konkrete:

1. Identifikimi i Hyrjeve të Dyshimta në Cloud
📌 Çfarë bën?

Analizon të dhëna si adresa IP, lokacioni, pajisja, ora e hyrjes dhe zbulon sjelljet e dyshimta.
Nëse një përdorues hyn nga një vend i pazakontë ose me IP të ndryshme shumë herë, sistemi e shënon si rrezik.
📌 Shembull:

Një përdorues zakonisht hyn nga Tirana me një Windows PC.
Papritur, ka një hyrje nga Kina me Linux – ky është një sulm i mundshëm.
Sistemi njofton administratorin ose bllokon hyrjen.
2. Parandalimi i Sulmeve DoS dhe Përdorimit të API-ve të Pasigurta
📌 Çfarë bën?

Monitoron numrin e hyrjeve të dështuara.
Nëse dikush provon të identifikohet 100 herë në minutë, kjo mund të jetë një sulm bruteforce.
Rrit sigurinë e API-ve duke analizuar përdorimin anormal.
📌 Shembull:

Një haker përpiqet të hyjë në një llogari duke testuar fjalëkalime të ndryshme.
Sistemi e kupton këtë model sjelljeje dhe bllokon IP-në.
3. Si Përdoret Deep Learning për të Rritur Sigurinë?
📌 Çfarë bën?

Përdor një rrjet nervor të thellë për të trajnuar modelin mbi të dhënat e hyrjeve normale dhe keqdashëse.
Përdor funksione si Swish Activation, Dropout, dhe Batch Normalization për të përmirësuar parashikimet.
Balancimi i të dhënave me SMOTE ndihmon që modeli të njohë edhe sulmet më pak të zakonshme.
📌 Shembull:

Trajnimi bëhet me të dhëna të vërteta nga një server cloud.
Kur një hyrje e re ndodh, modeli parashikon nëse është e sigurt apo e dyshimtë.
Nëse rezultati kalon pragun e rrezikut, bllokohet automatikisht ose dërgohet një alarm.
4. Transparenca dhe Interpretimi i Vendimeve me SHAP
📌 Çfarë bën?

Përdor SHAP (Shapley Additive Explanations) për të kuptuar pse një hyrje është klasifikuar si e rrezikshme.
📌 Shembull:

Një hyrje nga Francë me një VPN është klasifikuar si e rrezikshme.
SHAP tregon që ndryshimi i vendndodhjes dhe përdorimi i një pajisjeje të re ishin faktorët kryesorë.
5. Monitorim në Kohë Reale për Sulmet në Cloud
📌 Çfarë bën?

Mund të integrohet me sisteme cloud si AWS, Google Cloud, Azure për monitorim në kohë reale.
Nëse zbulohet një sulm ose aktivitet i dyshimtë, sistemi vepron automatikisht duke bllokuar hyrjen ose dërguar një alarm.
📌 Shembull:

Një haker po përpiqet të hyjë në një server cloud me një skript automatike.
Sistemi e njeh këtë model sjelljeje dhe ndalon sulmin përpara se të ndodhë dëmi.
Përfundim
✅ Përdor Deep Learning për të zbuluar hyrjet e rrezikshme.
✅ Mbron nga sulmet DoS dhe përdorimi i pasigurt i API-ve.
✅ Monitoron cloud në kohë reale dhe shpjegon vendimet me SHAP.
✅ Automatizon bllokimin e sulmeve pa ndërhyrje njerëzore.