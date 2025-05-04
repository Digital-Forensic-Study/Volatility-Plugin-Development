# Volatility-Plugin-Development
1 findpid.py
<br>
2 mmname.py: memmap의 프로세스 덤프 출력 간략화, 간편화(pid가 아닌 프로세스 이름으로 식별 후 덤프)

# Volatility 3 Plugin - 1 "findpid.py"
Windows 메모리 이미지에서 **부분 문자열 혹은 정확한 이름으로 프로세스를 찾고**, 해당 프로세스의 PID, 생성 및 종료 시간 정보를 출력하는 Volatility 3 플러그인을 개발(간단한 프로세스 탐지 도구)<br>
<ul>
  <li>프로세스 이름 입력 시 해당 프로세스의 PID 출력(간편하게 찾기, 프로세스 이름만 알고있다면 구지 pslist, psscan등을 입력하여 찾을 필요없음)</li>
  <li>부분만 입력해도 전체 프로세스 이름과 pid 모두 출력</li>
  <li>pslist 로직 기반</li>
    <ul>
      <li>ps관련 플러그인들 중에서 가장 빠름</li>
      <li>악의적인 행위 탐지 목적이 아니므로 프로세스 은닉 기법등은 배제</li>
    </ul>
</ul>

<br>

## 실행 예시

### 부분 일치
```bash
python vol.py -f <덤프파일> windows.findpid --name svch
```

### 정확 일치
```bash
python vol.py -f <덤프 파일> windows.findpid --name svchost --exact
```

<br>

## 기능 및 옵션

- `--name`: 프로세스 이름(부분 포함 가능)
- `--exact`: 정확히 일치하는 이름만 검색할 수 있도록 하는 옵션

<br>**출력 항목**: `ImageFileName`, `PID`, `CreateTime`, `ExitTime`

<br>

## 코드 구조

### 1. Import 및 기본 설정

```python
import datetime
import logging
from typing import Iterator

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist
```

- `pslist`의 EPROCESS 순회 로직 활용
- `utility.array_to_string()`으로 `ImageFileName` 추출

<br>

### 2. 플러그인 클래스 정의

```python
class FindPid(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)
```

- Volatility 3 플러그인으로 등록하기 위한 기본 상속 구조

<br>

### 3. 명령줄 옵션 정의

```python
@classmethod
def get_requirements(cls):
    return [
        requirements.ModuleRequirement(...),
        requirements.StringRequirement(...),
        requirements.BooleanRequirement(name="exact", ...)
    ]
```

- `--name`: 검색할 프로세스 이름 (필수)
- `--exact`: 이름이 정확히 일치할 때만 출력 (옵션)

<br>

### 4. 프로세스 탐색 및 필터링 로직

```python
for proc in pslist.PsList.list_processes(...):
    proc_name = utility.array_to_string(proc.ImageFileName)

    if exact_match:
        if proc_name.lower() != keyword:
            continue
    else:
        if keyword not in proc_name.lower():
            continue
```

- `pslist`의 `list_processes` 함수로 EPROCESS 리스트 획득
- 대소문자 무시 비교 수행
- `--exact` 여부에 따라 완전 일치 or 부분 포함 검색

<br>

### 5. 종료 시간 처리

```python
exit_time_obj = proc.get_exit_time()
if exit_time_obj and exit_time_obj.year > 1970:
    exit_time = exit_time_obj.strftime("%Y-%m-%d %H:%M:%S")
else:
    exit_time = "Running"
```

- 시스템 프로세스 등은 `ExitTime`이 0일 수 있음
- Unix epoch 이전이면 종료되지 않은 것으로 판단

<br>

### 6. 출력

```python
yield (0, (
    proc_name,
    pid,
    create_time.strftime(...),
    exit_time
))
```

- Volatility 3의 `TreeGrid` 출력 포맷: `(depth, (columns))`
- `TreeGrid`를 통해 표 형태로 출력
- `_generator()`에서 전달한 값과 정확히 일치해야 정상 출력됨

<br>

---
