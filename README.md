# BÀI TẬP MÔN AN TOÀN VÀ BẢO MẬT THÔNG TIN

## Thông tin sinh viên

**Họ và tên**:Đàm Ngọc Sơn  
**Lớp**: K59.KMT.K01 
**MSSV**:k235480106061

---

## I. Tìm hiểu thuật toán mã hoá hiện đại DES, AES

### 1. Thuật toán DES (Data Encryption Standard)

**Giới thiệu chung**

DES là thuật toán mã hoá khối (block cipher) đối xứng, được chuẩn hoá vào những năm 1970. DES mã hoá dữ liệu theo từng khối 64 bit, sử dụng khoá có độ dài 64 bit (nhưng chỉ 56 bit thực sự dùng để mã hoá, 8 bit còn lại là bit kiểm tra chẵn lẻ - parity bit).

**Cấu trúc thuật toán**

DES được xây dựng dựa trên **mạng Feistel (Feistel Network)**, gồm **16 vòng lặp (round)** giống hệt nhau về cấu trúc, chỉ khác khoá con sử dụng ở mỗi vòng.

Quy trình mã hoá một khối 64 bit:

1. Khối dữ liệu 64 bit đầu vào được đưa qua **hoán vị khởi tạo (Initial Permutation - IP)**.
2. Chia khối thành 2 nửa bằng nhau: `L0` (trái) và `R0` (phải), mỗi nửa 32 bit.
3. Thực hiện lặp lại 16 vòng, mỗi vòng thứ *i* thực hiện:
   - `Li = R(i-1)`
   - `Ri = L(i-1) XOR F(R(i-1), Ki)`

   Trong đó `F` là hàm mã hoá của DES, gồm các bước: mở rộng (Expansion) 32 bit thành 48 bit, XOR với khoá con `Ki` (48 bit), đưa qua 8 hộp thế **S-box** để nén lại 32 bit (đây là phần tạo tính phi tuyến, chống lại các phương pháp thám mã), rồi hoán vị **P-box**.
4. Sau vòng 16, ghép `R16` và `L16` lại (đảo ngược thứ tự so với các vòng trước) rồi đưa qua **hoán vị kết thúc (Final Permutation - IP⁻¹)** để ra bản mã 64 bit.

**Sinh khoá con (Key Schedule)**

- Khoá gốc 64 bit qua hoán vị **PC-1** (Permuted Choice 1), loại bỏ 8 bit parity còn 56 bit.
- Chia thành 2 nửa 28 bit, mỗi vòng dịch trái (Left Shift) 1 hoặc 2 bit tuỳ vòng.
- Sau mỗi lần dịch, ghép lại và đưa qua **PC-2** (Permuted Choice 2) để tạo ra khoá con 48 bit `Ki` dùng cho vòng đó.
- Kết quả: sinh ra 16 khoá con `K1...K16`, mỗi khoá dùng cho một vòng.

**Quy trình giải mã**

Giải mã DES dùng đúng thuật toán như mã hoá, chỉ khác: thứ tự sử dụng các khoá con bị **đảo ngược** (dùng `K16` trước, rồi `K15`, ..., cuối cùng là `K1`). Đây là ưu điểm của cấu trúc Feistel: mã hoá và giải mã dùng chung một thuật toán.

**Hạn chế**

Không gian khoá 56 bit (2⁵⁶ khả năng) quá nhỏ so với khả năng tính toán hiện đại, dễ bị tấn công vét cạn (brute-force). Năm 1998, máy "DES Cracker" đã phá được khoá DES trong vài giờ. Do đó DES hiện không còn được dùng để bảo vệ dữ liệu quan trọng; thay thế bằng **3DES** (áp dụng DES ba lần liên tiếp với các khoá khác nhau) hoặc **AES**.

---

### 2. Thuật toán AES (Advanced Encryption Standard)

**Giới thiệu chung**

AES được NIST chuẩn hoá năm 2001 để thay thế DES. Khác với DES, AES không dùng cấu trúc Feistel mà dùng **mạng thay thế - hoán vị (Substitution-Permutation Network - SPN)**.

- Kích thước khối dữ liệu cố định: **128 bit**.
- Độ dài khoá hỗ trợ: **128 / 192 / 256 bit**, tương ứng với số vòng lặp: **10 / 12 / 14 vòng**.
- Dữ liệu 128 bit được biểu diễn dưới dạng ma trận trạng thái (state) kích thước **4x4 byte**.

**Các bước biến đổi trong mỗi vòng**

Mỗi vòng (trừ vòng cuối cùng) gồm 4 phép biến đổi theo thứ tự:

1. **SubBytes**: thay thế từng byte trong ma trận trạng thái bằng giá trị tương ứng tra trong bảng **S-box** cố định. Đây là phép biến đổi phi tuyến duy nhất, giúp chống lại các kiểu tấn công tuyến tính/vi phân.
2. **ShiftRows**: dịch vòng (cyclic shift) từng hàng của ma trận trạng thái sang trái: hàng 0 giữ nguyên, hàng 1 dịch 1 byte, hàng 2 dịch 2 byte, hàng 3 dịch 3 byte.
3. **MixColumns**: nhân từng cột của ma trận trạng thái với một ma trận cố định trong trường hữu hạn GF(2⁸), tạo hiệu ứng khuếch tán (diffusion) - một bit thay đổi ở đầu vào sẽ ảnh hưởng tới nhiều byte đầu ra.
4. **AddRoundKey**: thực hiện phép XOR giữa ma trận trạng thái với khoá con (round key) của vòng hiện tại.

Vòng cuối cùng bỏ qua bước MixColumns (chỉ gồm SubBytes, ShiftRows, AddRoundKey).

**Sinh khoá con (Key Expansion)**

Từ khoá gốc, thuật toán **Key Expansion** sinh ra (số vòng + 1) khoá con 128 bit, sử dụng các hàm phụ trợ:

- `RotWord`: xoay vòng 4 byte của một từ (word).
- `SubWord`: áp dụng S-box lên từng byte của từ.
- `Rcon`: hằng số vòng (round constant), khác nhau ở mỗi vòng, dùng để tránh các khoá con bị đối xứng/lặp lại theo mẫu.

**Quy trình giải mã**

Giải mã thực hiện các phép biến đổi ngược, theo thứ tự ngược lại so với mã hoá:

- `InvShiftRows` (dịch vòng ngược hướng)
- `InvSubBytes` (dùng bảng S-box nghịch đảo)
- `AddRoundKey` (XOR nên tự nghịch đảo)
- `InvMixColumns` (nhân với ma trận nghịch đảo trong GF(2⁸))

Các khoá con được sử dụng theo thứ tự ngược (khoá của vòng cuối dùng trước).

**Chế độ hoạt động (Mode of Operation)**

Vì AES chỉ mã hoá được từng khối 128 bit, để mã hoá dữ liệu có độ dài bất kỳ cần áp dụng một *chế độ hoạt động*:

| Mode | Đặc điểm |
|---|---|
| ECB | Mỗi khối mã hoá độc lập - **không an toàn**, dễ lộ mẫu dữ liệu, không nên dùng |
| CBC | Mỗi khối XOR với khối mã trước đó trước khi mã hoá, cần vector khởi tạo (IV) ngẫu nhiên |
| CTR | Biến bộ đếm (counter) thành luồng khoá, cho phép mã hoá/giải mã song song |
| GCM | Kết hợp CTR với xác thực toàn vẹn dữ liệu (authenticated encryption) - khuyến nghị dùng hiện nay |

**So sánh nhanh DES và AES**

| Tiêu chí | DES | AES |
|---|---|---|
| Cấu trúc | Mạng Feistel | Mạng SPN |
| Kích thước khối | 64 bit | 128 bit |
| Độ dài khoá | 56 bit (hiệu dụng) | 128/192/256 bit |
| Số vòng | 16 | 10/12/14 |
| Độ an toàn hiện nay | Không an toàn (đã bị phá) | An toàn, đang là chuẩn quốc tế |

### 3. Cài đặt AES

Đã cài đặt minh hoạ thuật toán AES bằng ngôn ngữ **Python**, sử dụng thư viện `pycryptodome`, mã hoá/giải mã ở chế độ **CBC** với khoá 256 bit và IV ngẫu nhiên (xem file `aes_demo.py` đính kèm trong repo, thư mục `source-code/`).

Các bước chính trong code:

1. Sinh khoá AES 256 bit ngẫu nhiên bằng `get_random_bytes(32)`.
2. Hàm `aes_encrypt`: sinh IV ngẫu nhiên 16 byte, đệm dữ liệu theo chuẩn PKCS7, thực hiện mã hoá CBC, ghép IV + ciphertext rồi mã hoá base64 để tiện lưu trữ/truyền đi.
3. Hàm `aes_decrypt`: tách IV ra khỏi dữ liệu nhận được, giải mã CBC, loại bỏ padding, trả về bản rõ ban đầu.
4. Chương trình chính đo thời gian mã hoá và giải mã, so sánh với bản rõ gốc để kiểm tra tính đúng đắn.

---

## II. Tìm hiểu về thuật toán mã hoá bất đối xứng RSA

### Giới thiệu chung

RSA (Rivest - Shamir - Adleman) là thuật toán mã hoá **bất đối xứng (asymmetric)** đầu tiên được sử dụng rộng rãi, ra đời năm 1977. Khác với DES/AES dùng chung một khoá cho cả mã hoá và giải mã (đối xứng), RSA sử dụng **một cặp khoá**: khoá công khai (public key) và khoá bí mật (private key).

Độ an toàn của RSA dựa trên độ khó của bài toán **phân tích một số nguyên rất lớn thành thừa số nguyên tố** (Integer Factorization Problem): với n là tích của 2 số nguyên tố lớn, việc tìm lại 2 số nguyên tố đó từ n là cực kỳ khó nếu n đủ lớn (hiện nay thường dùng n có độ dài 2048 hoặc 4096 bit).

### Nguyên lý sinh cặp khoá bí mật, công khai

Quy trình sinh khoá RSA gồm các bước sau:

1. **Chọn 2 số nguyên tố lớn, ngẫu nhiên và khác nhau**: gọi là `p` và `q`.
2. **Tính modulus**: `n = p × q`. Giá trị `n` này được dùng làm phần chung của cả khoá công khai lẫn khoá bí mật. Độ dài bit của `n` chính là "độ dài khoá RSA" (ví dụ RSA-2048 nghĩa là `n` dài 2048 bit).
3. **Tính hàm Euler**: `φ(n) = (p - 1) × (q - 1)`. Đây là số lượng các số nguyên dương nhỏ hơn `n` và nguyên tố cùng nhau với `n`.
4. **Chọn số mũ công khai `e`**: sao cho `1 < e < φ(n)` và `gcd(e, φ(n)) = 1` (e nguyên tố cùng nhau với φ(n)). Trong thực tế, người ta thường chọn cố định `e = 65537` vì vừa đủ lớn để an toàn, vừa giúp việc mã hoá tính toán nhanh.
5. **Tính số mũ bí mật `d`**: là số sao cho `d × e ≡ 1 (mod φ(n))`, tức `d` là **nghịch đảo modulo** của `e` theo modulo `φ(n)`. Việc này được tính bằng **thuật toán Euclid mở rộng (Extended Euclidean Algorithm)`.
6. Kết quả cuối cùng:
   - **Khoá công khai (Public key)**: cặp `(e, n)` — được công bố rộng rãi cho bất kỳ ai.
   - **Khoá bí mật (Private key)**: cặp `(d, n)` — chỉ chủ sở hữu được giữ, tuyệt đối không tiết lộ.
   - Sau khi sinh khoá xong, `p`, `q` và `φ(n)` phải được huỷ bỏ an toàn (không lưu lại), vì nếu lộ ra thì có thể tính lại được `d`.

### Công thức mã hoá và giải mã

Với bản rõ `M` (được biểu diễn dưới dạng số nguyên nhỏ hơn `n`):

- **Mã hoá**: `C = M^e mod n`
- **Giải mã**: `M = C^d mod n`

Việc này đúng nhờ định lý Euler trong lý thuyết số: vì `d` và `e` được chọn sao cho `(M^e)^d ≡ M (mod n)`.

**Vì sao RSA an toàn?** Kẻ tấn công biết `n` và `e` (khoá công khai), nhưng để tính được `d` thì cần biết `φ(n)`, mà để tính `φ(n)` thì phải phân tích được `n` thành `p × q`. Với `n` đủ lớn (2048 bit trở lên), bài toán phân tích thừa số nguyên tố hiện chưa có thuật toán nào giải được trong thời gian khả thi bằng máy tính thông thường.

---

## III. Các mô hình áp dụng thuật toán RSA

### 1. Mô hình xác thực người nhận (bảo mật nội dung - Confidentiality)

- **Cách thực hiện**: Người gửi lấy **khoá công khai của người nhận** để mã hoá dữ liệu trước khi gửi đi.
- **Nguyên lý**: Vì chỉ có người nhận giữ khoá bí mật tương ứng, nên chỉ người nhận mới giải mã được nội dung.
- **Mục đích**: Đảm bảo tính bí mật — dù dữ liệu bị chặn trên đường truyền, kẻ tấn công cũng không đọc được nội dung.
- **Sơ đồ**: `Người gửi --[mã hoá bằng Public Key của B]--> Người nhận B --[giải mã bằng Private Key của B]--> Bản rõ`

### 2. Mô hình xác thực người gửi (chữ ký số - Authentication & Non-repudiation)

- **Cách thực hiện**: Người gửi dùng **khoá bí mật của chính mình** để "mã hoá" (thực chất là ký) lên dữ liệu (thường là mã băm/hash của dữ liệu, không ký trực tiếp lên dữ liệu gốc để tăng tốc độ).
- **Nguyên lý**: Bất kỳ ai cũng có thể dùng **khoá công khai của người gửi** để giải mã và kiểm tra chữ ký có khớp với dữ liệu hay không.
- **Mục đích**: Xác thực đúng là người gửi (vì chỉ người gửi có khoá bí mật đó) đã tạo ra dữ liệu này, và chống chối bỏ (người gửi không thể phủ nhận đã gửi).
- **Sơ đồ**: `Người gửi A --[ký bằng Private Key của A]--> Chữ ký số --[người nhận xác minh bằng Public Key của A]--> Xác nhận đúng nguồn gốc`

### 3. Mô hình kết hợp cả hai (vừa bảo mật, vừa xác thực)

Áp dụng đồng thời cả 2 mô hình trên để đạt cả tính bí mật lẫn xác thực nguồn gốc:

1. Người gửi A tính hash của dữ liệu, ký bằng **private key của A** → được chữ ký số.
2. Gộp dữ liệu gốc + chữ ký số, sau đó mã hoá toàn bộ bằng **public key của người nhận B**.
3. Gửi đi.
4. Người nhận B giải mã bằng **private key của B** → lấy lại được dữ liệu gốc + chữ ký.
5. B dùng **public key của A** để xác minh chữ ký, đảm bảo dữ liệu đúng là do A gửi và không bị thay đổi trên đường truyền.

→ Mô hình này đảm bảo đồng thời: **Confidentiality** (chỉ B đọc được) + **Authentication** (chắc chắn do A gửi) + **Integrity** (dữ liệu không bị sửa đổi) + **Non-repudiation** (A không thể chối là đã gửi).

### 4. So sánh thời gian mã hoá/giải mã của RSA với AES

Từ kết quả thực nghiệm chạy chương trình benchmark (file `rsa_and_benchmark.py`, cùng dữ liệu đầu vào, RSA-2048 và AES-256):

| Thuật toán | Thời gian mã hoá | Thời gian giải mã |
|---|---|---|
| AES-256 | ~0.04 ms | ~0.05 ms |
| RSA-2048 | ~0.49 ms | ~1.19 ms |

**Nhận xét:**

- AES nhanh hơn RSA rất nhiều lần (thực nghiệm cho thấy RSA giải mã chậm hơn AES khoảng **20-25 lần** với cùng khối lượng dữ liệu nhỏ), vì AES chỉ thực hiện các phép toán đơn giản (XOR, thay thế bảng tra, hoán vị) trên từng byte, trong khi RSA phải tính luỹ thừa modulo với số rất lớn (hàng nghìn bit), là phép toán tốn nhiều chi phí tính toán hơn nhiều.
- RSA còn bị giới hạn về kích thước dữ liệu có thể mã hoá trực tiếp (nhỏ hơn kích thước khoá `n`, ví dụ RSA-2048 + OAEP chỉ mã hoá được tối đa khoảng 190 byte một lần), nên **không phù hợp để mã hoá trực tiếp dữ liệu lớn**.
- AES phù hợp mã hoá khối lượng dữ liệu lớn với tốc độ cao, nhưng có nhược điểm là cần trao đổi khoá bí mật trước giữa 2 bên một cách an toàn (bài toán phân phối khoá).

### 5. Mô hình kết hợp sức mạnh của RSA và AES (Hybrid Encryption)

Đây là mô hình được ứng dụng phổ biến nhất trong thực tế (giao thức TLS/HTTPS, PGP, S/MIME...), tận dụng ưu điểm của cả hai thuật toán: **tốc độ của AES** và **khả năng trao đổi khoá an toàn của RSA**.

**Quy trình:**

1. Bên gửi sinh ra một **khoá AES ngẫu nhiên** (gọi là "session key" - khoá phiên), chỉ dùng một lần cho phiên giao tiếp này.
2. Dùng khoá AES đó để mã hoá **toàn bộ dữ liệu cần gửi** (nhanh, không giới hạn kích thước dữ liệu).
3. Dùng **khoá công khai RSA của bên nhận** để mã hoá **khoá AES** (vì khoá AES thường nhỏ, chỉ 16/32 byte nên RSA xử lý rất nhanh).
4. Gửi đi gói tin gồm: `{dữ liệu đã mã hoá bằng AES} + {khoá AES đã được mã hoá bằng RSA}`.
5. Bên nhận: dùng **khoá bí mật RSA của mình** để giải mã ra khoá AES gốc, sau đó dùng khoá AES đó để giải mã phần dữ liệu chính.

**Lợi ích của mô hình kết hợp:**

- Giải quyết được bài toán trao đổi khoá bí mật một cách an toàn mà không cần 2 bên gặp nhau trước (nhờ RSA).
- Vẫn giữ được tốc độ xử lý cao khi mã hoá khối lượng dữ liệu lớn (nhờ AES).
- Đây chính là nguyên lý hoạt động cốt lõi trong bắt tay TLS (TLS Handshake) khi trình duyệt kết nối HTTPS tới máy chủ.

Đã cài đặt minh hoạ mô hình Hybrid Encryption này trong file `rsa_and_benchmark.py` (hàm `hybrid_encrypt` và `hybrid_decrypt`), cùng với minh hoạ ký số (`sign_message`, `verify_signature`) cho mô hình xác thực người gửi.

---


