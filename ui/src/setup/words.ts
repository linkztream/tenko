// The word list of the generated passphrase (Hardened profile): common English words of 4 to
// 8 letters, lowercase a to z only, no brand words and nothing offensive. Four words from
// this list give about 41 bits of entropy (log2 of the list length, times four); the
// passphrase is hashed with Argon2id, checked against the breached-password corpus and is
// longer than the 16 characters the preset asks for. words.test.ts keeps the list clean:
// no duplicates, only the allowed letters.

const LIST = `
acorn adobe agate alder almond amber anchor angle antler apple apricot arbor arch arrow aspen
atlas aurora autumn avenue badger bagel baker bamboo banjo barley barrel basalt basil basket
beacon beaver beetle bishop bison blanket blossom bluff bonsai border bottle boulder bracket
bramble branch brass breeze bridge bronze brook bucket buffalo bundle butter button cabin cactus
camel candle canoe canvas canyon carbon cargo carpet carrot castle cattle cavern cedar celery
cellar cement cereal chalk chapel charm cherry chest chimney cider cinder circle citrus clay
clever cliff clock cloud clover cobalt cobweb cocoa coconut comet compass copper coral cotton
cougar cove coyote cradle crane crater creek crest cricket crimson crown crystal cuckoo curtain
cypress daisy dancer dapple dawn delta denim desert diamond dolphin donkey dragon drift drizzle
drum dune dusk eagle earth echo eclipse elbow elder ember emerald engine falcon fable feather
fennel fern ferry fiddle field figure finch fjord flame flannel flint flute forest fossil fountain
frost galaxy garden garlic garnet gazelle ginger glacier glade glider globe glove goblet goose
gorge granite grape gravel griffin grove guitar gull hammer harbor harp harvest hawk hazel heather
helmet heron hickory hill hollow honey horizon hornet hound hummus iceberg igloo indigo inlet iris
island ivory jackal jacket jade jaguar jasper jelly jigsaw jungle juniper kayak kelp kernel kettle
kiwi koala ladder lagoon lake lamp lantern larch lark laurel lava lemon lentil lichen lilac lily
linen lizard llama lobster locust lotus lumber lynx magnet mango mantle maple marble marsh meadow
melon mercury mesa meteor millet mint mirror mist mitten mocha monarch moose mosaic moss moth
mountain muffin mulberry nectar needle nickel nimbus nutmeg oasis ocean olive onion opal orange
orbit orchard orchid osprey otter oyster paddle palace palm panda panther paper parade parrot
pasture peach pearl pebble pelican pepper pewter phoenix piano picnic pigeon pillow pine pioneer
planet plateau plum plume pocket polar pollen pond poplar poppy prairie prism pumpkin puzzle quail
quartz quilt quince rabbit radish raft rain rainbow raisin ranger raven reed reef ribbon ridge
river robin rocket rosemary rowan ruby saddle saffron sage sailor salmon sand sapphire satin
scarlet seal sequoia shadow shell shore shrimp signal silk silver skiff sled slate sleet slope
smoke snow sorrel sparrow spice spider spiral sponge spring spruce squash squirrel stable star
steam steel stone storm stream summit sunrise sunset swan swift sycamore tablet talon teal temple
thimble thistle thorn thunder tide tiger timber toast topaz torch tower trail trellis trout
trumpet tulip tundra turnip turtle twilight umber valley vanilla velvet verbena vessel violet
vista volcano vulture wagon walnut walrus warbler water wave weasel wheat whistle willow window
winter wisteria wolf wombat wren yarrow yacht yellow zebra zephyr zinc absorb accent access active
adapt admire advice affect agree alarm album alert alike amuse animal annual answer anthem anyway
appear argue arrive ascend attend august awake aware bargain basic beauty become before behind
belong beside better beyond bicycle bitter blend bloom board borrow bounce brave bright broad
brush build burst busy calm camp carry catch cause change charge chase cheer choose circus claim
clean clear climb close coach collect color combine comfort common concert connect copy corner
count courage cover craft create credit cross crowd cruise curious custom cycle damp dance decide
deep define delay deliver depart depend design detail dinner direct dismiss divide dollar double
doubt draft dream dress drive during easy effort eight either empty enable endure enjoy enough
enter equal escape even every exact excuse exist expand expect explain explore extra fabric faint
fairly famous fancy farmer fast favor feast fetch fifth final finish firm first flash flat float
flood floor flow flower fluent focus follow forget formal forward fresh friend frozen fruit funny
future gather gentle giant gift glad glow golden govern grace grain grand grant great green greet
group grow guard guess guest guide happy hardly health heavy height hidden hobby honest hope human
hungry hurry idea image impact imply inch income indeed inform inner input inside invent invite
issue jolly journey joyful judge juice jump just keen keep kind kitchen knack knit label lack
large later laugh launch layer leader learn leave legend lesson letter level light limit linger
listen little lively local lofty logic lonely long loose lucky lunar magic major maker manage
margin market master matter maybe measure member mention merry method middle might mild mind minor
minute modern moment month morning motion mount move much music narrow nation native nature nearby
neat neither never nice noble normal notice novel number object obtain occur offer often only open
option order other outer owner pace packet paint pair panel partner party patch path pause peace
people perfect period permit person phrase pick piece pilot pitch place plain plan plant play
please pledge plenty point polish popular portal poster pour power praise prepare present pretty
price pride prime print prize profit promise proof proper proud provide public pull pure purple
purpose quick quiet quote radio raise range rapid rare rather reach ready real reason recall
record reduce refer reflect refresh region relax release rely remain remark remember remind remove
repair repeat reply report rescue reserve resolve rest result return reveal reward rhythm rich
ride right ring rise ritual roam roast robust rough round route royal rural safe salad same sample
satisfy save scale scene school science scout screen script search season second secret section
select send sense series serve settle seven shape share sharp shine ship shiny shop short should
show shut sight silent simple since single sister sixty skill sleep slender slim slow small smart
smile smooth snack social soft solar solid solve some song soon sound source space spare speak
special speed spend spirit split sport spot spread square stage stamp stand start state station
stay steady step stick still stock stop store story straight strange street strength strike strong
student study style subject succeed sudden sugar suit sunny super supply support sure surface
surprise sweet swim switch symbol table tackle talent tall taste teach team tell tender thank
theme there thing think third thirty though three thrive throw ticket tidy tight time tiny today
together token tomorrow tool topic total touch tough toward trace trade train travel treat trend
trial tribe trick trust truth tune turn twelve twenty twice uncle under unique unit unless until
upon upper urban usual useful vacant valid value variety various vast very view village visit
vital voice voyage wait wake walk wander warm watch weave wedding week welcome well western whale
wheel where which while white whole wide wild wind wise wish within wonder wood word work world
worth write wrong yearly young youth zero zone anvil bagpipe ballad barn beam bell bench berry
blade blaze bolt bonfire brick brisk cable cake camera candy cane cart chain chair cheese chess
chip chord cloak coast coin comb cone cook cork couch crab crate cream crisp crumb cube curve
dairy dart dash deck desk dial dice dish dive dock doll door dove draw drill dust dwarf easel fair
farm fence film fish flag flask fleet flour fork frame fudge gadget gale gate gear glass glue
grill hall hinge hoop hose hotel hull inkwell jazz jewel kite knot lace lawn leaf lens lime lock
loft loop mail mask maze meal mill mine mold nail nest nook note oven pack page pail pier pipe
plate plow plug pole pool port quest rack rake ramp rattle rice rock roof rope rose sack sail salt
sauce scarf seed shed shelf shield shirt shoe sieve sink skate slice sock soda soup spade spoon
spool stool straw sunbeam swing sword tack tart tent thread throne tile tire tray tube twig
umbrella vase vest vine wall wand whip wick wire wool yarn yoke
`;

/** The words, lowercase, in the order of the list above. */
export const WORDS: readonly string[] = LIST.split(/\s+/).filter((w) => w.length > 0);
