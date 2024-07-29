from Crypto.Util.number import bytes_to_long, getPrime, long_to_bytes

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

mods = [130776209750577749835030120177960711260746973465933970554603211093202241849140283963070975869880197967636679882459425232357950636079269818278568331668998063928156173195959380304140630764464229048280039196174920973123835445919754900176667008119897242692086059168797053268156792975204964947627089008375799703487, 106039908807682295118508391943059019922115877016091451126257844269275794363081344088697227412755529762417766096181138288866006649365769949594005021220973430687200374786021517369375111264528926768533498850679704723231483969210338899014821680268027400146301596065417519481392990782491665307410984810594847541973, 131889892801951057653240072390356045725331217054137619551467698848786008012839094175616469405280910484659955131415729713269733993088088502972173147791248377899723609672917146181723966430625176574573071425027700213671657374588659565583762627949615176966169262006583974952060449860770052389703276660033107003407, 130776209750577749835030120177960711260746973465933970554603211093202241849140283963070975869880197967636679882459425232357950636079269818278568331668998063928156173195959380304140630764464229048280039196174920973123835445919754900176667008119897242692086059168797053268156792975204964947627089008375799703487, 83514529542378539715485465104705226931091902434960317044056787105820911937408042230106726375672664845042951951727903342871495151187065846167709552480150823077455641653253261962250498904074423653835449161730640812700784961597975604342072361411227564716721774443492153733282886053513512683452684163835534128229, 137785349308107085445167594062037277209484583999652178333859913862244135227886543195956033770272937887766584944420753138388682122019760598323369252953355873008375242262897311017794300503849969133021481352113757862991536114264447415875487413410667044955349205636540219851412670526786363357683213748246410089283]
cs = [71488404123474011084101940066301601067418088732310685471978990271545081444405266259256152251681281349467980616622309843588642173301964832853565318824633097499390473014604007790964266188643060338299041213614112086917887934129409801065917674204120703242235602654697877120382999519001926661684305478520536441195, 9030333609424097939010024733948158819520513095690855750727609234322945421430646609924848563029289491082678960749926975884640686325489183072306395041451883568111621014963583321671828188931331813204457024273879552882801742662633458174659655537363779418871815321050106935464872643430942976611512539851484837690, 14116443625039907240111952181592490567213119733775841674116445005849040974441286047442048091057413976402623391644036923010047594604320510827326115631781966857846687398573940803559041677795029732433206560402931885224689380900269081600544330644090298091953834813340216482034658598921739077003193963332042099988, 71488404123474011084101940066301601067418088732310685471978990271545081444405266259256152251681281349467980616622309843588642173301964832853565318824633097499390473014604007790964266188643060338299041213614112086917887934129409801065917674204120703242235602654697877120382999519001926661684305478520536441195, 57623938630901461789946750235864911203162107496488550728905142716985817579530432818024666833314172989108427066334606249935456271894156535465432257838884923815609493683785019436543264518004997559698881570269338749475131238255480389338939275904138939518247109893131435688332767357407230305216850750649884393574, 100542356150760678934106100190458590316156166981789493516399665979728531704629991835291978126042716530884602678388692919779710917611906400662554227343010587093760587653253967031135204985627674843452803954198271869600969923266678959768996110869746562797296803362880116117556901919034484012151803908101940941621]
e = 65537

found = False
for i in range(0, 6):
    for j in range(i + 1, 6):
        if mods[i] == mods[j]:
            continue
        (g, u, v) = egcd(min(mods[i], mods[j]), max(mods[i], mods[j]))
        if g != 1:
            found = True
            mod1 = i
            mod2 = j
            p = g
            break
    if found: 
        break

print(mod1)
print(mod2)
q = mods[mod1] // p   

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

m = pow(cs[mod1], d, mods[mod1])
f = long_to_bytes(m)
print(f)