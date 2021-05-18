from SPEAR.spear import *

key = "La4ISB68xyT2wQev9SILibkczLt8m4DOrPg8fN5C90o="

spear_1 = Spear('itx-test', 'spear-1', network_encryption=key, use_local=False, relays=[ip()])
spear_2 = Spear('itx-test', 'spear-2', network_encryption=key, use_local=False, relays=[ip()])
spear_1.serve_forever()
spear_2.serve_forever()
print('pausing for 5s')
time.sleep(5)
print(spear_1.peers)
print(spear_2.peers)

@spear_2.target('echo')
def echo(*args, **kwargs):
    del kwargs['node']
    del kwargs['originator']
    return [args, kwargs]

while True:
    try:
        print(spear_1.peer().command('echo', 1, 2, 3, item=5))
    except:
        traceback.print_exc()
    time.sleep(2)