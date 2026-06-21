import json, re, time, urllib.parse, urllib.request
path=r'e:\eProject\eGatefilter\filter\claude.ai\i18n\en-US.json'
backup=r'e:\eProject\eGatefilter\filter\claude.ai\i18n\en-US.json.bak'
with open(path,'r',encoding='utf-8') as f:
    data=json.load(f)
with open(backup,'w',encoding='utf-8') as f:
    json.dump(data,f,ensure_ascii=False,indent=2)

def need_translate(s):
    if not isinstance(s,str):
        return False
    return bool(re.search('[A-Za-z]', s)) and not bool(re.search('[\u4e00-\u9fff]', s))

keys=[k for k,v in data.items() if need_translate(v)]
print('to translate:', len(keys))

skipset={
    '{change, number, ::sign-always}',
    '{count} standard seats',
    '{n, plural, one {an agent} other {# agents}}',
    '{daysRemaining} trial days remaining',
}

for idx,k in enumerate(keys, start=1):
    orig=data[k]
    if len(orig.strip()) == 0 or orig.strip() in skipset:
        continue
    placeholders = {}
    def repl_ph(m):
        token=f'__PH{len(placeholders)}__'
        placeholders[token]=m.group(0)
        return token
    text=re.sub(r'{[^}]+}|<[^>]+>', repl_ph, orig)
    tr=None
    for attempt in range(8):
        try:
            q=urllib.parse.urlencode({'q': text,'langpair':'en-US|zh-CN'})
            url='https://api.mymemory.translated.net/get?'+q
            with urllib.request.urlopen(url, timeout=30) as resp:
                res=json.loads(resp.read().decode('utf-8'))
            tr=res.get('responseData',{}).get('translatedText','')
            if tr:
                break
        except Exception as e:
            if isinstance(e, urllib.error.HTTPError) and e.code == 429:
                sleep_time = 10 + attempt * 5
                print('rate limit 429, sleeping', sleep_time, 'seconds')
                time.sleep(sleep_time)
                continue
            if attempt < 7:
                time.sleep(2 + attempt*2)
                continue
            print('fail', idx, k, e)
            tr=orig
    if not tr:
        tr = orig
    for token,src in placeholders.items():
        tr = tr.replace(token, src)
    if tr and tr != orig:
        data[k]=tr
    if idx % 100 == 0:
        print('progress', idx, '/', len(keys), 'left', len(keys)-idx)
        with open(path,'w',encoding='utf-8') as f:
            json.dump(data,f,ensure_ascii=False,indent=2)
    time.sleep(0.2)
with open(path,'w',encoding='utf-8') as f:
    json.dump(data,f,ensure_ascii=False,indent=2)
print('done')
