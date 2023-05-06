
Saldırı Tespit sistemi:

Saldırı Tespit Sistemi (Intrusion Detection System - IDS), ağa yapılan saldırıları tespit edebilmek ve saldırıların izlenmesini sağlayabilmek için kullanılan bir araçtır. IDS, ağ trafiğini izleyerek, ağa yapılan saldırılar veya istenmeyen etkinlikleri tespit eder ve alarm verir.

IDS, farklı şekillerde uygulanabilir. En basit uygulama, ağ trafiğini izlemek için bir ağ monitörü kullanmaktır. Ağ monitörü, ağ trafiğini izler ve izlenen tüm paketleri toplar. IDS, bu toplanan verileri analiz eder ve ağa yönelik saldırıları tespit etmeye çalışır. Bu tespitler sonrasında, bir alarm oluşturarak kullanıcıları uyarmaktadır.

IDS, pasif veya aktif olarak çalışabilir. Pasif IDS, ağ trafiğini sadece izlerken, aktif IDS, tespit edilen saldırılara yanıt verir. Örneğin, bir saldırı tespit edildiğinde, saldırganın IP adresini bloke edebilir veya saldırıya karşı önlem alabilir.

IDS, çeşitli algoritmalar kullanarak saldırıları tespit edebilir. Bunlar, önceden tanımlanmış imza tabanlı algılayıcılar veya davranış tabanlı algılayıcılar gibi çeşitli teknikler kullanabilir. Önceden tanımlanmış imza tabanlı algılayıcılar, bilinen saldırıların imzalarını tanımlayarak tespit ederken, davranış tabanlı algılayıcılar, normal ağ trafiğini analiz ederek anormal etkinlikleri tespit etmeye çalışır.

IDS, ağdaki tehditleri tespit ederek proaktif bir yaklaşım benimseyerek güvenliği artırabilir. Bu sayede, ağ yöneticileri olası saldırıları önceden tespit edebilir ve önleyebilir. IDS, ayrıca mevcut ağ güvenlik politikalarının etkililiğini de ölçebilir ve bu politikaları geliştirmek için veri sağlar.



Yöntem, İzlenecek Yol ve Kullanılacak Kütüphaneler:


Projede kullanabileceğiniz bazı Python kütüphaneleri şunlar olabilir:

1.Scapy: Bu kütüphane, ağ trafiğini dinleyebilir ve filtreleyebilir, ayrıştırabilir ve oluşturabilir.

2.Pyshark: Bu kütüphane, Python üzerinden Wireshark'ın kullanılmasına olanak tanır ve ağ trafiğini analiz etmek için kullanılabilir.

3.PyQT5: Bu kütüphane, Python uygulamaları için kullanıcı arayüzü bileşenleri sağlar.

4.SQLite: Bu küçük veritabanı, proje için kullanılabilecek bir yerel veritabanı çözümü sağlar.

5.Bro: Ağ analizi ve güvenliği için kullanılan ücretsiz ve açık kaynaklı bir yazılım. Bro, ağ trafiğini analiz etmek için çok güçlü bir araçtır.

6.Suricata: Açık kaynaklı bir ağ saldırı tespit sistemi (IDS) olan Suricata, ağ trafiğini izler ve saldırı işaretlerini tespit eder.

7.Zeek: Önceden Bro olarak bilinen Zeek, ağ trafiğini analiz etmek ve saldırıları tespit etmek için kullanılan bir araçtır.

Bu kütüphaneleri kullanarak, ağ trafiği analiz edilebilir, tespit edilen saldırılar veritabanına kaydedilebilir ve bir kullanıcı arayüzü ile sonuçlar gösterilebilir.

