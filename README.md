# Volatility3-Plugin-Development
1. findpid.py <br>
2. mmname.py
<br>

## 플러그인 경로
```bash
C:\volatility3-2.11.0\volatility3\framework\plugins\windows
```
---
<br>

# Volatility 3 Plugin - 1 "findpid.py"
Windows 메모리 이미지에서 **부분 문자열 혹은 정확한 이름으로 프로세스를 찾고**, 해당 프로세스의 PID, 생성 및 종료 시간 정보를 출력하는 Volatility 3 플러그인을 개발(간단한 프로세스 탐지 도구)<br>
<ul>
  <li>프로세스 이름 입력 시 해당 프로세스의 PID 출력(간편하게 찾기, 프로세스 이름만 알고있다면 굳이 pslist, psscan등을 입력하여 찾을 필요없음)</li>
  <li>부분만 입력해도 전체 프로세스 이름과 pid 모두 출력</li>
  <li>pslist 로직 기반</li>
    <ul>
      <li>ps관련 플러그인들 중에서 가장 빠름</li>
      <li>악의적인 행위 탐지 목적이 아니므로 프로세스 은닉 기법등은 배제</li>
    </ul>
</ul>
<br>

## 기능 및 옵션

- `--name`: 프로세스 이름(부분 포함 가능)
- `--exact`: 정확히 일치하는 이름만 검색할 수 있도록 하는 옵션

<br>**출력 항목**: `ImageFileName`, `PID`, `CreateTime`, `ExitTime`

<br>

## 실행 예시

### 부분 일치
```bash
python vol.py -f <덤프 파일> windows.findpid --name svch
```

### 정확 일치
```bash
python vol.py -f <덤프 파일> windows.findpid --name svchost.exe --exact
```

--- 
<br>

# Volatility 3 Plugin - 2 "mmname.py"
Windows 메모리 이미지에서 **정확한 프로세스 이름을 통해**, 해당 프로세스의 메모리맵을 출력하거나 덤프하는 Volatility 3 플러그인을 개발(프로세스 이름으로 덤프하는 도구) <br>
<ul>
  <li>프로세스 이름 입력 시 해당 프로세스의 메모리맵 출력과 덤프 (굳이 pslist, psscan등을 입력하여 pid를 찾을 필요없음)</li>
  <li>프로세스 이름이 다수 일 땐 해당하는 모든 프로세스 덤프</li>
  <li>프로세스 이름으로 해당 프로세스 목록 출력</li>
  <li>프로세스 이름이 다수 일 땐 하나 혹은 원하는 다수의 프로세스를 선택하여 덤프가능</li>
  <li>pslist 로직 기반</li>
    <ul>
      <li>ps관련 플러그인들 중에서 가장 빠름</li>
    </ul>
</ul>

<br>

## 기능 및 옵션

- `--name`: 프로세스 이름으로 메모리맵 출력 (정확한 이름)
- `--dump`: 프로세스 이름으로 덤프
- `--list`: 메모리맵 출력 없이 해당 프로세스 이름을 가진 목록 출력
- `--select-pid`: 같은 프로세스 이름이 여러개일 때, 하나 혹은 여러개의 pid를 지정하여 사용

<br>**출력 항목**: `ImageFileName`, `PID`, `CreateTime`, `ExitTime`
<br>**덤프 되는 파일명**: `pid.<PID>.dmp`

<br>

## 실행 예시

### --name
```bash
python vol.py -f <덤프 파일> windows.mmname --name svchost.exe
```

### --dump
```bash
python vol.py -f <덤프 파일> windows.mmname --name svchost.exe --dump
```

### --list
```bash
python vol.py -f <덤프 파일> windows.mmname --name svchost.exe --list
```

### --select-pid
```bash
python vol.py -f <덤프 파일> windows.mmname --name svchost.exe --select-pid <PID>
```
```bash
python vol.py -f <덤프 파일> windows.mmname --name svchost.exe --select-pid <PID> --dump
```
```bash
python vol.py -f <덤프 파일> windows.mmname --name svchost.exe --select-pid <PID> <PID> --dump
```
