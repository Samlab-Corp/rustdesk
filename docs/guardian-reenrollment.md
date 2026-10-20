# Guardian 재등록 전용 보호 통로

일반 터미널·관리 명령과 분리된 개발 전용 통로입니다. 실제 기기, 서비스, 암호 변경 또는 설치를 이 문서의 검증으로 주장하지 않습니다. 기존 원격 복구 통로는 보존합니다.

## 실행 계약

`samlab-terminal --guardian-reenrollment-probe --target <주소>` 또는 `--guardian-reenrollment`만 사용합니다. 선택 `--force-relay` 외 경로·명령·시간 인수는 없습니다. 표준입력의 정확한 상위 필드는 `password`, 선택 `connection_token`, 실행 시 필수 `delegation_token`, `delivery_id`, `guardian_sha256`, `action`, `scope`입니다. 조회에는 위임 자격을 받지 않습니다. `scope`는 Guardian의 엄격한 낙타표기 계약 그대로이며 환경은 `development`만 허용합니다. 비밀을 명령 인수·파일·터미널·오류 출력에 넣지 않습니다.

기존 암호화 연결과 새 암호 검증을 유지합니다. `Terminal.reenrollment`는 다른 전용 통로와 동시에 선택할 수 없습니다. 실제 SYSTEM 수신기는 현재 과정 번호와 `ProcessIdToSessionId` 실측값을 반환합니다. 세션 번호가 0이라는 가정은 하지 않습니다. 터미널을 열거나 사용자 자식을 만들지 않습니다.

기능 조회는 고정 `SamlabGuardian` 서비스와 `\\.\pipe\samlab-guardian-native-remote-v1`의 실제 서버, SYSTEM, 보호된 ProgramFiles 실행파일, 열린 파일 식별·접근 제어·해시를 확인합니다. Guardian의 `guardian-reenrollment-capability`가 동일 전체 귀속·행동·고정 해시를 확인한 뒤만 난수32바이트 도전값을 보냅니다. 구 수신기는 이 기능 응답이 없으므로 승인 발급 전 차단됩니다.

실행은 고정 개발 주소 `/v2/kiosk/device/guardian-reenrollment/management-grant`에 위임 자격으로 단 한 번 요청합니다. 본문은 `deliveryId`, 실제 `challenge`, 고정 `commandHash`입니다. 승인 응답의 유닉스초 만료·행동·작업·전달·해시를 확인합니다. 60초 승인 수명을 확장하지 않습니다. Guardian이 같은 전체 귀속과 별도 목적 승인을 직접 온라인 소비합니다. 목적은 `samlab-guardian-reenrollment-v1`이며 행동 해시는 UTF8 정확 문자열 `{"action":"prepare","protocolVersion":1,"purpose":"samlab-guardian-reenrollment-v1"}`의 SHA256입니다. 다른 행동은 action 값만 바꿉니다. 호출자의 임의 명령 해시는 불허합니다.

수신기는 전달 번호를 한 번 예약하고 동일 연결의 도전값을 한 번 소비합니다. 고정 Guardian 파이프 실행만 최대90초 기다리며 원시 출력은 반환하지 않습니다. 클라이언트 전체 상한은150초, 연결·기능 응답 대기는45초, 발급15초, 전달 후95초입니다. 일반 관리 명령의 제한은 변경하지 않습니다. 유실·시간 초과·부정확 응답은 `uncertain`이며 같은 실행을 다시 보내지 않습니다. 후속 새 status만 상위 조정기의 목적별 승인으로 요청합니다.

## 공개 결과

정확한 상위16필드는 `reenrollmentVersion`, `status`, `reason`, `deliveryId`, `operationId`, `action`, `scope`, `commandHash`, `guardianSha256`, `executorIsSystem`, `executorProcessId`, `executorSessionId`, `nonPty`, `capability`, `receipt`, `responseConfirmed`입니다. 상태는 `supported`, `completed`, `unavailable`, `uncertain`, `rejected`입니다. 기능 조회의 capability는 `{purpose,challenge,addressId,guardian}`이며 guardian은 엄격한 공개 기능 응답입니다. 실제 실행 receipt는 Guardian `Response`의 엄격한 공개 개체입니다. `completed`는 전달 응답 확인이고 중앙 확정은 receipt의 `phase=committed`, `verified=true`와 새 암호 일치/옛 암호 불일치 증거로 별도 판단합니다. 성공 status의 observed.localPhase는 실제 Guardian이 반환하는 commit 직전 `rotated` 증거일 수 있습니다. 시각은 최근120초/미래5초 이내여야 합니다. 알려지지 않은 필드·비밀 필드·중복 필드는 거절합니다.

## 공급자 원자 교체

설치된 `ProgramFiles\RustDesk\RustDesk.exe`의 고정 `--reenrollment-password-cas-stdin` 및 `--reenrollment-password-status-stdin`는 기존 Flutter 실행파일이 새 `librustdesk.dll`의 `rustdesk_core_main_args`를 사용자 화면보다 먼저 호출하는 진입점을 사용합니다. PC9 전용 명령 실행파일을 시험기기에 설치했다고 가정하지 않습니다. 실제 제품의 내보내기와 구 실행파일/새 DLL 결합의 부정 경로 실행 증거는 별도 제작 증거에 남깁니다.

정확한 표준입력6필드는 `old_password,new_password,operation_id,old_enrollment_id,new_enrollment_id,expected_address_id`입니다. 일반 설치의 blank-or-same 및 수동 암호 설정 동작은 바꾸지 않습니다. 실제 SYSTEM·고정 설치 경로·살아 있는 SCM 서비스·주소·회사 서버 검증 후 기존 구성 쓰기 잠금 아래에서 old→new 비교 교체를 단 한 번 수행합니다. 공급자 잠금은 진행 중 교체와 관측을 배제하며 해당 작업 번호는 교체 전 예약합니다. 새 암호 확인은 데몬 메모리와 실제 영구 파일 둘 다 일치해야 합니다. 진행 중 잠금·저장 실패·응답 유실은 확정하지 않습니다. Guardian의 durable Applying 원장이 재시작 뒤 재교체를 막는 정본입니다.

공개 응답은 `casVersion,status,reason,operationId,oldEnrollmentId,newEnrollmentId,addressId,daemonAccepted,persisted,newMatches,oldMatches,rotationInFlight,serverVerified`뿐입니다. 원문 자격은 반환하지 않습니다. status가 observed라도 모든 실제 검증 표시와 새 암호 일치/옛 암호 불일치를 상위에서 대조해야 합니다.
