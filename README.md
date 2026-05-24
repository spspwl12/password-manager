# Win32 Secure Password Manager

A lightweight, extremely secure, and standalone password manager for Windows written entirely in pure C using the native Win32 API and BCrypt. No external dependencies, frameworks, or third-party libraries are required.

## 🚀 주요 기능 (Features)

*   **강력한 암호화 (Advanced Security):**
    *   Windows 기본 내장 암호화 라이브러리인 **BCrypt API** 사용.
    *   **AES-256-CBC** 알고리즘을 사용한 데이터 암호화.
    *   **PBKDF2-HMAC-SHA256** (10만 번 반복) 알고리즘을 이용한 안전한 마스터 키 도출.
    *   **HMAC-SHA256**을 이용한 금고 파일(`vault.dat`) 무결성 및 변조 방지 검증.
*   **완벽한 메모리 보안 (Memory Safety):**
    *   메모리 스캔 공격을 방지하기 위해 사용이 끝난 비밀번호나 암호화 키는 즉시 `SecureZeroMemory`를 통해 메모리에서 영구 삭제.
*   **클립보드 보호 (Clipboard Protection):**
    *   클립보드에 복사된 아이디/비밀번호는 10초 후 자동으로 클립보드에서 삭제되어 유출 방지.
*   **드래그 앤 드롭 (OLE Drag & Drop):**
    *   리스트에서 아이디나 비밀번호를 마우스로 클릭한 채 웹 브라우저나 로그인 창으로 바로 끌어다 놓아(Drag & Drop) 입력 가능. (순수 C 언어로 OLE COM 인터페이스 자체 구현)

## 📂 파일 구조 (File Structure)

*   `main.c` - 메인 애플리케이션 로직, UI 이벤트 핸들링, 파일 입출력 및 OLE Drag & Drop COM 구현부
*   `crypto.c` / `crypto.h` - BCrypt 기반 AES, PBKDF2, HMAC, 난수 생성 등 암호화 모듈 구현부
*   `resource.rc` / `resource.h` - Windows 다이얼로그 템플릿, 아이콘, 단축키 및 UI 컨트롤 리소스 정의

## 🛠️ 빌드 방법 (How to Build)

* 본 프로젝트는 Visual Studio (MSVC) 환경에서 컴파일되도록 설계되었습니다.
* password-manager.vcxproj 로 프로젝트를 열어 컴파일 하면 됩니다.

## 📖 사용 방법 (Usage)

1. **초기 설정:** 프로그램을 처음 실행하면 새로운 마스터 비밀번호를 설정하는 창이 뜹니다.
2. **항목 추가/수정/삭제:** 목록에서 우클릭이나 하단 버튼을 통해 저장할 계정 정보를 관리합니다.
3. **입력 활용:**
   - **버튼 복사:** `ID 복사` / `PW 복사` 버튼 클릭 후 10초 내에 원하는 곳에 붙여넣기.
   - **단축키 입력:** 로그인할 웹사이트를 열어두고 단축키(`Ctrl+Alt+1/2/3`)를 누르기.
   - **드래그 앤 드롭:** 리스트에서 아이디나 비밀번호 항목을 꾹 누른 채로 원하는 브라우저 텍스트 박스에 끌어다 놓기.

## ⚠️ 주의 사항 (Security Notice)

이 프로젝트는 학습 및 개인 사용 목적으로 심플하게 개발되었습니다. 최신 보안 기법들이 적용되어 있으나, 마스터 비밀번호를 분실할 경우 파일(`vault.dat`)에 저장된 데이터는 **어떤 방법으로도 복구할 수 없습니다.** 백업과 관리에 주의하시기 바랍니다.
