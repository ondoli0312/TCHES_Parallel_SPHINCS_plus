#include "type.cuh"
#include "CPU.c"

typedef struct {
    unsigned char   Key[32];
    unsigned char   V[16];
    int             reseed_counter;
    uint32_t		rk[60];
} AES256_CTR_DRBG_struct;

__constant__ unsigned int  shared_Te0[256] = {
    0xc66363a5U, 0xf87c7c84U, 0xee777799U, 0xf67b7b8dU,
    0xfff2f20dU, 0xd66b6bbdU, 0xde6f6fb1U, 0x91c5c554U,
    0x60303050U, 0x02010103U, 0xce6767a9U, 0x562b2b7dU,
    0xe7fefe19U, 0xb5d7d762U, 0x4dababe6U, 0xec76769aU,
    0x8fcaca45U, 0x1f82829dU, 0x89c9c940U, 0xfa7d7d87U,
    0xeffafa15U, 0xb25959ebU, 0x8e4747c9U, 0xfbf0f00bU,
    0x41adadecU, 0xb3d4d467U, 0x5fa2a2fdU, 0x45afafeaU,
    0x239c9cbfU, 0x53a4a4f7U, 0xe4727296U, 0x9bc0c05bU,
    0x75b7b7c2U, 0xe1fdfd1cU, 0x3d9393aeU, 0x4c26266aU,
    0x6c36365aU, 0x7e3f3f41U, 0xf5f7f702U, 0x83cccc4fU,
    0x6834345cU, 0x51a5a5f4U, 0xd1e5e534U, 0xf9f1f108U,
    0xe2717193U, 0xabd8d873U, 0x62313153U, 0x2a15153fU,
    0x0804040cU, 0x95c7c752U, 0x46232365U, 0x9dc3c35eU,
    0x30181828U, 0x379696a1U, 0x0a05050fU, 0x2f9a9ab5U,
    0x0e070709U, 0x24121236U, 0x1b80809bU, 0xdfe2e23dU,
    0xcdebeb26U, 0x4e272769U, 0x7fb2b2cdU, 0xea75759fU,
    0x1209091bU, 0x1d83839eU, 0x582c2c74U, 0x341a1a2eU,
    0x361b1b2dU, 0xdc6e6eb2U, 0xb45a5aeeU, 0x5ba0a0fbU,
    0xa45252f6U, 0x763b3b4dU, 0xb7d6d661U, 0x7db3b3ceU,
    0x5229297bU, 0xdde3e33eU, 0x5e2f2f71U, 0x13848497U,
    0xa65353f5U, 0xb9d1d168U, 0x00000000U, 0xc1eded2cU,
    0x40202060U, 0xe3fcfc1fU, 0x79b1b1c8U, 0xb65b5bedU,
    0xd46a6abeU, 0x8dcbcb46U, 0x67bebed9U, 0x7239394bU,
    0x944a4adeU, 0x984c4cd4U, 0xb05858e8U, 0x85cfcf4aU,
    0xbbd0d06bU, 0xc5efef2aU, 0x4faaaae5U, 0xedfbfb16U,
    0x864343c5U, 0x9a4d4dd7U, 0x66333355U, 0x11858594U,
    0x8a4545cfU, 0xe9f9f910U, 0x04020206U, 0xfe7f7f81U,
    0xa05050f0U, 0x783c3c44U, 0x259f9fbaU, 0x4ba8a8e3U,
    0xa25151f3U, 0x5da3a3feU, 0x804040c0U, 0x058f8f8aU,
    0x3f9292adU, 0x219d9dbcU, 0x70383848U, 0xf1f5f504U,
    0x63bcbcdfU, 0x77b6b6c1U, 0xafdada75U, 0x42212163U,
    0x20101030U, 0xe5ffff1aU, 0xfdf3f30eU, 0xbfd2d26dU,
    0x81cdcd4cU, 0x180c0c14U, 0x26131335U, 0xc3ecec2fU,
    0xbe5f5fe1U, 0x359797a2U, 0x884444ccU, 0x2e171739U,
    0x93c4c457U, 0x55a7a7f2U, 0xfc7e7e82U, 0x7a3d3d47U,
    0xc86464acU, 0xba5d5de7U, 0x3219192bU, 0xe6737395U,
    0xc06060a0U, 0x19818198U, 0x9e4f4fd1U, 0xa3dcdc7fU,
    0x44222266U, 0x542a2a7eU, 0x3b9090abU, 0x0b888883U,
    0x8c4646caU, 0xc7eeee29U, 0x6bb8b8d3U, 0x2814143cU,
    0xa7dede79U, 0xbc5e5ee2U, 0x160b0b1dU, 0xaddbdb76U,
    0xdbe0e03bU, 0x64323256U, 0x743a3a4eU, 0x140a0a1eU,
    0x924949dbU, 0x0c06060aU, 0x4824246cU, 0xb85c5ce4U,
    0x9fc2c25dU, 0xbdd3d36eU, 0x43acacefU, 0xc46262a6U,
    0x399191a8U, 0x319595a4U, 0xd3e4e437U, 0xf279798bU,
    0xd5e7e732U, 0x8bc8c843U, 0x6e373759U, 0xda6d6db7U,
    0x018d8d8cU, 0xb1d5d564U, 0x9c4e4ed2U, 0x49a9a9e0U,
    0xd86c6cb4U, 0xac5656faU, 0xf3f4f407U, 0xcfeaea25U,
    0xca6565afU, 0xf47a7a8eU, 0x47aeaee9U, 0x10080818U,
    0x6fbabad5U, 0xf0787888U, 0x4a25256fU, 0x5c2e2e72U,
    0x381c1c24U, 0x57a6a6f1U, 0x73b4b4c7U, 0x97c6c651U,
    0xcbe8e823U, 0xa1dddd7cU, 0xe874749cU, 0x3e1f1f21U,
    0x964b4bddU, 0x61bdbddcU, 0x0d8b8b86U, 0x0f8a8a85U,
    0xe0707090U, 0x7c3e3e42U, 0x71b5b5c4U, 0xcc6666aaU,
    0x904848d8U, 0x06030305U, 0xf7f6f601U, 0x1c0e0e12U,
    0xc26161a3U, 0x6a35355fU, 0xae5757f9U, 0x69b9b9d0U,
    0x17868691U, 0x99c1c158U, 0x3a1d1d27U, 0x279e9eb9U,
    0xd9e1e138U, 0xebf8f813U, 0x2b9898b3U, 0x22111133U,
    0xd26969bbU, 0xa9d9d970U, 0x078e8e89U, 0x339494a7U,
    0x2d9b9bb6U, 0x3c1e1e22U, 0x15878792U, 0xc9e9e920U,
    0x87cece49U, 0xaa5555ffU, 0x50282878U, 0xa5dfdf7aU,
    0x038c8c8fU, 0x59a1a1f8U, 0x09898980U, 0x1a0d0d17U,
    0x65bfbfdaU, 0xd7e6e631U, 0x844242c6U, 0xd06868b8U,
    0x824141c3U, 0x299999b0U, 0x5a2d2d77U, 0x1e0f0f11U,
    0x7bb0b0cbU, 0xa85454fcU, 0x6dbbbbd6U, 0x2c16163aU,
};
__constant__ unsigned int  shared_Te1[256] = {
   0xa5c66363U, 0x84f87c7cU, 0x99ee7777U, 0x8df67b7bU,
   0x0dfff2f2U, 0xbdd66b6bU, 0xb1de6f6fU, 0x5491c5c5U,
   0x50603030U, 0x03020101U, 0xa9ce6767U, 0x7d562b2bU,
   0x19e7fefeU, 0x62b5d7d7U, 0xe64dababU, 0x9aec7676U,
   0x458fcacaU, 0x9d1f8282U, 0x4089c9c9U, 0x87fa7d7dU,
   0x15effafaU, 0xebb25959U, 0xc98e4747U, 0x0bfbf0f0U,
   0xec41adadU, 0x67b3d4d4U, 0xfd5fa2a2U, 0xea45afafU,
   0xbf239c9cU, 0xf753a4a4U, 0x96e47272U, 0x5b9bc0c0U,
   0xc275b7b7U, 0x1ce1fdfdU, 0xae3d9393U, 0x6a4c2626U,
   0x5a6c3636U, 0x417e3f3fU, 0x02f5f7f7U, 0x4f83ccccU,
   0x5c683434U, 0xf451a5a5U, 0x34d1e5e5U, 0x08f9f1f1U,
   0x93e27171U, 0x73abd8d8U, 0x53623131U, 0x3f2a1515U,
   0x0c080404U, 0x5295c7c7U, 0x65462323U, 0x5e9dc3c3U,
   0x28301818U, 0xa1379696U, 0x0f0a0505U, 0xb52f9a9aU,
   0x090e0707U, 0x36241212U, 0x9b1b8080U, 0x3ddfe2e2U,
   0x26cdebebU, 0x694e2727U, 0xcd7fb2b2U, 0x9fea7575U,
   0x1b120909U, 0x9e1d8383U, 0x74582c2cU, 0x2e341a1aU,
   0x2d361b1bU, 0xb2dc6e6eU, 0xeeb45a5aU, 0xfb5ba0a0U,
   0xf6a45252U, 0x4d763b3bU, 0x61b7d6d6U, 0xce7db3b3U,
   0x7b522929U, 0x3edde3e3U, 0x715e2f2fU, 0x97138484U,
   0xf5a65353U, 0x68b9d1d1U, 0x00000000U, 0x2cc1ededU,
   0x60402020U, 0x1fe3fcfcU, 0xc879b1b1U, 0xedb65b5bU,
   0xbed46a6aU, 0x468dcbcbU, 0xd967bebeU, 0x4b723939U,
   0xde944a4aU, 0xd4984c4cU, 0xe8b05858U, 0x4a85cfcfU,
   0x6bbbd0d0U, 0x2ac5efefU, 0xe54faaaaU, 0x16edfbfbU,
   0xc5864343U, 0xd79a4d4dU, 0x55663333U, 0x94118585U,
   0xcf8a4545U, 0x10e9f9f9U, 0x06040202U, 0x81fe7f7fU,
   0xf0a05050U, 0x44783c3cU, 0xba259f9fU, 0xe34ba8a8U,
   0xf3a25151U, 0xfe5da3a3U, 0xc0804040U, 0x8a058f8fU,
   0xad3f9292U, 0xbc219d9dU, 0x48703838U, 0x04f1f5f5U,
   0xdf63bcbcU, 0xc177b6b6U, 0x75afdadaU, 0x63422121U,
   0x30201010U, 0x1ae5ffffU, 0x0efdf3f3U, 0x6dbfd2d2U,
   0x4c81cdcdU, 0x14180c0cU, 0x35261313U, 0x2fc3ececU,
   0xe1be5f5fU, 0xa2359797U, 0xcc884444U, 0x392e1717U,
   0x5793c4c4U, 0xf255a7a7U, 0x82fc7e7eU, 0x477a3d3dU,
   0xacc86464U, 0xe7ba5d5dU, 0x2b321919U, 0x95e67373U,
   0xa0c06060U, 0x98198181U, 0xd19e4f4fU, 0x7fa3dcdcU,
   0x66442222U, 0x7e542a2aU, 0xab3b9090U, 0x830b8888U,
   0xca8c4646U, 0x29c7eeeeU, 0xd36bb8b8U, 0x3c281414U,
   0x79a7dedeU, 0xe2bc5e5eU, 0x1d160b0bU, 0x76addbdbU,
   0x3bdbe0e0U, 0x56643232U, 0x4e743a3aU, 0x1e140a0aU,
   0xdb924949U, 0x0a0c0606U, 0x6c482424U, 0xe4b85c5cU,
   0x5d9fc2c2U, 0x6ebdd3d3U, 0xef43acacU, 0xa6c46262U,
   0xa8399191U, 0xa4319595U, 0x37d3e4e4U, 0x8bf27979U,
   0x32d5e7e7U, 0x438bc8c8U, 0x596e3737U, 0xb7da6d6dU,
   0x8c018d8dU, 0x64b1d5d5U, 0xd29c4e4eU, 0xe049a9a9U,
   0xb4d86c6cU, 0xfaac5656U, 0x07f3f4f4U, 0x25cfeaeaU,
   0xafca6565U, 0x8ef47a7aU, 0xe947aeaeU, 0x18100808U,
   0xd56fbabaU, 0x88f07878U, 0x6f4a2525U, 0x725c2e2eU,
   0x24381c1cU, 0xf157a6a6U, 0xc773b4b4U, 0x5197c6c6U,
   0x23cbe8e8U, 0x7ca1ddddU, 0x9ce87474U, 0x213e1f1fU,
   0xdd964b4bU, 0xdc61bdbdU, 0x860d8b8bU, 0x850f8a8aU,
   0x90e07070U, 0x427c3e3eU, 0xc471b5b5U, 0xaacc6666U,
   0xd8904848U, 0x05060303U, 0x01f7f6f6U, 0x121c0e0eU,
   0xa3c26161U, 0x5f6a3535U, 0xf9ae5757U, 0xd069b9b9U,
   0x91178686U, 0x5899c1c1U, 0x273a1d1dU, 0xb9279e9eU,
   0x38d9e1e1U, 0x13ebf8f8U, 0xb32b9898U, 0x33221111U,
   0xbbd26969U, 0x70a9d9d9U, 0x89078e8eU, 0xa7339494U,
   0xb62d9b9bU, 0x223c1e1eU, 0x92158787U, 0x20c9e9e9U,
   0x4987ceceU, 0xffaa5555U, 0x78502828U, 0x7aa5dfdfU,
   0x8f038c8cU, 0xf859a1a1U, 0x80098989U, 0x171a0d0dU,
   0xda65bfbfU, 0x31d7e6e6U, 0xc6844242U, 0xb8d06868U,
   0xc3824141U, 0xb0299999U, 0x775a2d2dU, 0x111e0f0fU,
   0xcb7bb0b0U, 0xfca85454U, 0xd66dbbbbU, 0x3a2c1616U,
};
__constant__ unsigned int  shared_Te2[256] = {
   0x63a5c663U, 0x7c84f87cU, 0x7799ee77U, 0x7b8df67bU,
   0xf20dfff2U, 0x6bbdd66bU, 0x6fb1de6fU, 0xc55491c5U,
   0x30506030U, 0x01030201U, 0x67a9ce67U, 0x2b7d562bU,
   0xfe19e7feU, 0xd762b5d7U, 0xabe64dabU, 0x769aec76U,
   0xca458fcaU, 0x829d1f82U, 0xc94089c9U, 0x7d87fa7dU,
   0xfa15effaU, 0x59ebb259U, 0x47c98e47U, 0xf00bfbf0U,
   0xadec41adU, 0xd467b3d4U, 0xa2fd5fa2U, 0xafea45afU,
   0x9cbf239cU, 0xa4f753a4U, 0x7296e472U, 0xc05b9bc0U,
   0xb7c275b7U, 0xfd1ce1fdU, 0x93ae3d93U, 0x266a4c26U,
   0x365a6c36U, 0x3f417e3fU, 0xf702f5f7U, 0xcc4f83ccU,
   0x345c6834U, 0xa5f451a5U, 0xe534d1e5U, 0xf108f9f1U,
   0x7193e271U, 0xd873abd8U, 0x31536231U, 0x153f2a15U,
   0x040c0804U, 0xc75295c7U, 0x23654623U, 0xc35e9dc3U,
   0x18283018U, 0x96a13796U, 0x050f0a05U, 0x9ab52f9aU,
   0x07090e07U, 0x12362412U, 0x809b1b80U, 0xe23ddfe2U,
   0xeb26cdebU, 0x27694e27U, 0xb2cd7fb2U, 0x759fea75U,
   0x091b1209U, 0x839e1d83U, 0x2c74582cU, 0x1a2e341aU,
   0x1b2d361bU, 0x6eb2dc6eU, 0x5aeeb45aU, 0xa0fb5ba0U,
   0x52f6a452U, 0x3b4d763bU, 0xd661b7d6U, 0xb3ce7db3U,
   0x297b5229U, 0xe33edde3U, 0x2f715e2fU, 0x84971384U,
   0x53f5a653U, 0xd168b9d1U, 0x00000000U, 0xed2cc1edU,
   0x20604020U, 0xfc1fe3fcU, 0xb1c879b1U, 0x5bedb65bU,
   0x6abed46aU, 0xcb468dcbU, 0xbed967beU, 0x394b7239U,
   0x4ade944aU, 0x4cd4984cU, 0x58e8b058U, 0xcf4a85cfU,
   0xd06bbbd0U, 0xef2ac5efU, 0xaae54faaU, 0xfb16edfbU,
   0x43c58643U, 0x4dd79a4dU, 0x33556633U, 0x85941185U,
   0x45cf8a45U, 0xf910e9f9U, 0x02060402U, 0x7f81fe7fU,
   0x50f0a050U, 0x3c44783cU, 0x9fba259fU, 0xa8e34ba8U,
   0x51f3a251U, 0xa3fe5da3U, 0x40c08040U, 0x8f8a058fU,
   0x92ad3f92U, 0x9dbc219dU, 0x38487038U, 0xf504f1f5U,
   0xbcdf63bcU, 0xb6c177b6U, 0xda75afdaU, 0x21634221U,
   0x10302010U, 0xff1ae5ffU, 0xf30efdf3U, 0xd26dbfd2U,
   0xcd4c81cdU, 0x0c14180cU, 0x13352613U, 0xec2fc3ecU,
   0x5fe1be5fU, 0x97a23597U, 0x44cc8844U, 0x17392e17U,
   0xc45793c4U, 0xa7f255a7U, 0x7e82fc7eU, 0x3d477a3dU,
   0x64acc864U, 0x5de7ba5dU, 0x192b3219U, 0x7395e673U,
   0x60a0c060U, 0x81981981U, 0x4fd19e4fU, 0xdc7fa3dcU,
   0x22664422U, 0x2a7e542aU, 0x90ab3b90U, 0x88830b88U,
   0x46ca8c46U, 0xee29c7eeU, 0xb8d36bb8U, 0x143c2814U,
   0xde79a7deU, 0x5ee2bc5eU, 0x0b1d160bU, 0xdb76addbU,
   0xe03bdbe0U, 0x32566432U, 0x3a4e743aU, 0x0a1e140aU,
   0x49db9249U, 0x060a0c06U, 0x246c4824U, 0x5ce4b85cU,
   0xc25d9fc2U, 0xd36ebdd3U, 0xacef43acU, 0x62a6c462U,
   0x91a83991U, 0x95a43195U, 0xe437d3e4U, 0x798bf279U,
   0xe732d5e7U, 0xc8438bc8U, 0x37596e37U, 0x6db7da6dU,
   0x8d8c018dU, 0xd564b1d5U, 0x4ed29c4eU, 0xa9e049a9U,
   0x6cb4d86cU, 0x56faac56U, 0xf407f3f4U, 0xea25cfeaU,
   0x65afca65U, 0x7a8ef47aU, 0xaee947aeU, 0x08181008U,
   0xbad56fbaU, 0x7888f078U, 0x256f4a25U, 0x2e725c2eU,
   0x1c24381cU, 0xa6f157a6U, 0xb4c773b4U, 0xc65197c6U,
   0xe823cbe8U, 0xdd7ca1ddU, 0x749ce874U, 0x1f213e1fU,
   0x4bdd964bU, 0xbddc61bdU, 0x8b860d8bU, 0x8a850f8aU,
   0x7090e070U, 0x3e427c3eU, 0xb5c471b5U, 0x66aacc66U,
   0x48d89048U, 0x03050603U, 0xf601f7f6U, 0x0e121c0eU,
   0x61a3c261U, 0x355f6a35U, 0x57f9ae57U, 0xb9d069b9U,
   0x86911786U, 0xc15899c1U, 0x1d273a1dU, 0x9eb9279eU,
   0xe138d9e1U, 0xf813ebf8U, 0x98b32b98U, 0x11332211U,
   0x69bbd269U, 0xd970a9d9U, 0x8e89078eU, 0x94a73394U,
   0x9bb62d9bU, 0x1e223c1eU, 0x87921587U, 0xe920c9e9U,
   0xce4987ceU, 0x55ffaa55U, 0x28785028U, 0xdf7aa5dfU,
   0x8c8f038cU, 0xa1f859a1U, 0x89800989U, 0x0d171a0dU,
   0xbfda65bfU, 0xe631d7e6U, 0x42c68442U, 0x68b8d068U,
   0x41c38241U, 0x99b02999U, 0x2d775a2dU, 0x0f111e0fU,
   0xb0cb7bb0U, 0x54fca854U, 0xbbd66dbbU, 0x163a2c16U,
};
__constant__ unsigned int  shared_Te3[256] = {
   0x6363a5c6U, 0x7c7c84f8U, 0x777799eeU, 0x7b7b8df6U,
   0xf2f20dffU, 0x6b6bbdd6U, 0x6f6fb1deU, 0xc5c55491U,
   0x30305060U, 0x01010302U, 0x6767a9ceU, 0x2b2b7d56U,
   0xfefe19e7U, 0xd7d762b5U, 0xababe64dU, 0x76769aecU,
   0xcaca458fU, 0x82829d1fU, 0xc9c94089U, 0x7d7d87faU,
   0xfafa15efU, 0x5959ebb2U, 0x4747c98eU, 0xf0f00bfbU,
   0xadadec41U, 0xd4d467b3U, 0xa2a2fd5fU, 0xafafea45U,
   0x9c9cbf23U, 0xa4a4f753U, 0x727296e4U, 0xc0c05b9bU,
   0xb7b7c275U, 0xfdfd1ce1U, 0x9393ae3dU, 0x26266a4cU,
   0x36365a6cU, 0x3f3f417eU, 0xf7f702f5U, 0xcccc4f83U,
   0x34345c68U, 0xa5a5f451U, 0xe5e534d1U, 0xf1f108f9U,
   0x717193e2U, 0xd8d873abU, 0x31315362U, 0x15153f2aU,
   0x04040c08U, 0xc7c75295U, 0x23236546U, 0xc3c35e9dU,
   0x18182830U, 0x9696a137U, 0x05050f0aU, 0x9a9ab52fU,
   0x0707090eU, 0x12123624U, 0x80809b1bU, 0xe2e23ddfU,
   0xebeb26cdU, 0x2727694eU, 0xb2b2cd7fU, 0x75759feaU,
   0x09091b12U, 0x83839e1dU, 0x2c2c7458U, 0x1a1a2e34U,
   0x1b1b2d36U, 0x6e6eb2dcU, 0x5a5aeeb4U, 0xa0a0fb5bU,
   0x5252f6a4U, 0x3b3b4d76U, 0xd6d661b7U, 0xb3b3ce7dU,
   0x29297b52U, 0xe3e33eddU, 0x2f2f715eU, 0x84849713U,
   0x5353f5a6U, 0xd1d168b9U, 0x00000000U, 0xeded2cc1U,
   0x20206040U, 0xfcfc1fe3U, 0xb1b1c879U, 0x5b5bedb6U,
   0x6a6abed4U, 0xcbcb468dU, 0xbebed967U, 0x39394b72U,
   0x4a4ade94U, 0x4c4cd498U, 0x5858e8b0U, 0xcfcf4a85U,
   0xd0d06bbbU, 0xefef2ac5U, 0xaaaae54fU, 0xfbfb16edU,
   0x4343c586U, 0x4d4dd79aU, 0x33335566U, 0x85859411U,
   0x4545cf8aU, 0xf9f910e9U, 0x02020604U, 0x7f7f81feU,
   0x5050f0a0U, 0x3c3c4478U, 0x9f9fba25U, 0xa8a8e34bU,
   0x5151f3a2U, 0xa3a3fe5dU, 0x4040c080U, 0x8f8f8a05U,
   0x9292ad3fU, 0x9d9dbc21U, 0x38384870U, 0xf5f504f1U,
   0xbcbcdf63U, 0xb6b6c177U, 0xdada75afU, 0x21216342U,
   0x10103020U, 0xffff1ae5U, 0xf3f30efdU, 0xd2d26dbfU,
   0xcdcd4c81U, 0x0c0c1418U, 0x13133526U, 0xecec2fc3U,
   0x5f5fe1beU, 0x9797a235U, 0x4444cc88U, 0x1717392eU,
   0xc4c45793U, 0xa7a7f255U, 0x7e7e82fcU, 0x3d3d477aU,
   0x6464acc8U, 0x5d5de7baU, 0x19192b32U, 0x737395e6U,
   0x6060a0c0U, 0x81819819U, 0x4f4fd19eU, 0xdcdc7fa3U,
   0x22226644U, 0x2a2a7e54U, 0x9090ab3bU, 0x8888830bU,
   0x4646ca8cU, 0xeeee29c7U, 0xb8b8d36bU, 0x14143c28U,
   0xdede79a7U, 0x5e5ee2bcU, 0x0b0b1d16U, 0xdbdb76adU,
   0xe0e03bdbU, 0x32325664U, 0x3a3a4e74U, 0x0a0a1e14U,
   0x4949db92U, 0x06060a0cU, 0x24246c48U, 0x5c5ce4b8U,
   0xc2c25d9fU, 0xd3d36ebdU, 0xacacef43U, 0x6262a6c4U,
   0x9191a839U, 0x9595a431U, 0xe4e437d3U, 0x79798bf2U,
   0xe7e732d5U, 0xc8c8438bU, 0x3737596eU, 0x6d6db7daU,
   0x8d8d8c01U, 0xd5d564b1U, 0x4e4ed29cU, 0xa9a9e049U,
   0x6c6cb4d8U, 0x5656faacU, 0xf4f407f3U, 0xeaea25cfU,
   0x6565afcaU, 0x7a7a8ef4U, 0xaeaee947U, 0x08081810U,
   0xbabad56fU, 0x787888f0U, 0x25256f4aU, 0x2e2e725cU,
   0x1c1c2438U, 0xa6a6f157U, 0xb4b4c773U, 0xc6c65197U,
   0xe8e823cbU, 0xdddd7ca1U, 0x74749ce8U, 0x1f1f213eU,
   0x4b4bdd96U, 0xbdbddc61U, 0x8b8b860dU, 0x8a8a850fU,
   0x707090e0U, 0x3e3e427cU, 0xb5b5c471U, 0x6666aaccU,
   0x4848d890U, 0x03030506U, 0xf6f601f7U, 0x0e0e121cU,
   0x6161a3c2U, 0x35355f6aU, 0x5757f9aeU, 0xb9b9d069U,
   0x86869117U, 0xc1c15899U, 0x1d1d273aU, 0x9e9eb927U,
   0xe1e138d9U, 0xf8f813ebU, 0x9898b32bU, 0x11113322U,
   0x6969bbd2U, 0xd9d970a9U, 0x8e8e8907U, 0x9494a733U,
   0x9b9bb62dU, 0x1e1e223cU, 0x87879215U, 0xe9e920c9U,
   0xcece4987U, 0x5555ffaaU, 0x28287850U, 0xdfdf7aa5U,
   0x8c8c8f03U, 0xa1a1f859U, 0x89898009U, 0x0d0d171aU,
   0xbfbfda65U, 0xe6e631d7U, 0x4242c684U, 0x6868b8d0U,
   0x4141c382U, 0x9999b029U, 0x2d2d775aU, 0x0f0f111eU,
   0xb0b0cb7bU, 0x5454fca8U, 0xbbbbd66dU, 0x16163a2cU,
};
__constant__ unsigned int  rcon[11] = {
    0x00000000, 0x01000000, 0x02000000, 0x04000000,
    0x08000000, 0x10000000, 0x20000000, 0x40000000,
    0x80000000, 0x1b000000, 0x36000000
};

__device__ uint32_t load_bigendian_32(uint8_t* x) {
    return (uint32_t)(x[3]) | (((uint32_t)(x[2])) << 8) |
        (((uint32_t)(x[1])) << 16) | (((uint32_t)(x[0])) << 24);
}
__device__ uint64_t load_bigendian_64(uint8_t* x) {
    return (uint64_t)(x[7]) | (((uint64_t)(x[6])) << 8) |
        (((uint64_t)(x[5])) << 16) | (((uint64_t)(x[4])) << 24) |
        (((uint64_t)(x[3])) << 32) | (((uint64_t)(x[2])) << 40) |
        (((uint64_t)(x[1])) << 48) | (((uint64_t)(x[0])) << 56);
}
__device__ void store_bigendian_32(uint8_t* x, uint64_t u) {
    x[3] = (uint8_t)u;
    u >>= 8;
    x[2] = (uint8_t)u;
    u >>= 8;
    x[1] = (uint8_t)u;
    u >>= 8;
    x[0] = (uint8_t)u;
}
__device__ void store_bigendian_64(uint8_t* x, uint64_t u) {
    x[7] = (uint8_t)u;
    u >>= 8;
    x[6] = (uint8_t)u;
    u >>= 8;
    x[5] = (uint8_t)u;
    u >>= 8;
    x[4] = (uint8_t)u;
    u >>= 8;
    x[3] = (uint8_t)u;
    u >>= 8;
    x[2] = (uint8_t)u;
    u >>= 8;
    x[1] = (uint8_t)u;
    u >>= 8;
    x[0] = (uint8_t)u;
}

__device__ void u32_to_bytes(uint8_t* out, uint32_t in) {
    out[0] = (uint8_t)(in >> 24);
    out[1] = (uint8_t)(in >> 16);
    out[2] = (uint8_t)(in >> 8);
    out[3] = (uint8_t)in;
}
__device__ void ull_to_bytes(uint8_t* out, uint32_t outlen, uint64_t in)
{
    int i;
    for (i = outlen - 1; i >= 0; i--) {
        out[i] = in & 0xff;
        in = in >> 8;
    }
}
__device__ void set_type(uint32_t* addr, uint32_t type) {
    ((uint8_t*)addr)[SPX_OFFSET_TYPE] = type;
}
__device__ void set_tree_height(uint32_t* addr, uint32_t tree_height) {
    ((uint8_t*)addr)[SPX_OFFSET_TREE_HGT] = tree_height;
}
__device__ void set_tree_index(uint32_t* addr, uint32_t tree_index) {
    u32_to_bytes(&((uint8_t*)addr)[SPX_OFFSET_TREE_INDEX], tree_index);
}
__device__ void set_tree_addr(uint32_t* addr, uint64_t tree) {
    ull_to_bytes(&((unsigned char*)addr)[SPX_OFFSET_TREE], 8, tree);
}
__device__ void set_layer_addr(uint32_t* addr, uint32_t layer) {
    ((uint8_t*)addr)[SPX_OFFSET_LAYER] = layer;
}
__device__ void set_keypair_addr(uint32_t* addr, uint32_t keypair) {
    ((uint8_t*)addr)[SPX_OFFSET_KP_ADDR1] = keypair;
}
__device__ void set_chain_addr(uint32_t* addr, uint32_t chain) {
    ((uint8_t*)addr)[SPX_OFFSET_CHAIN_ADDR] = chain;
}
__device__ void set_hash_addr(uint32_t* addr, uint32_t hash) {
    ((uint8_t*)addr)[SPX_OFFSET_HASH_ADDR] = hash;
}
__device__ void copy_keypair_addr(uint32_t* out, uint32_t* in) {
    for (int i = 0; i < SPX_OFFSET_TREE + 8; i++)
        ((uint8_t*)out)[i] = ((uint8_t*)in)[i];
    ((uint8_t*)out)[SPX_OFFSET_KP_ADDR1] = ((uint8_t*)in)[SPX_OFFSET_KP_ADDR1];
}
__device__ void copy_subtree_addr(uint32_t* out, uint32_t* in) {
    for (int i = 0; i < (SPX_OFFSET_TREE + 8); i++)
        ((uint8_t*)out)[i] = ((uint8_t*)in)[i];
}

__constant__ uint8_t iv_256[32] = {
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19
};
__device__ size_t crypto_hashblock_sha256(uint8_t* statebytes, uint8_t* in, size_t inlen) {
    uint32_t state[8];
    uint32_t a = load_bigendian_32(statebytes + 0); state[0] = a;
    uint32_t b = load_bigendian_32(statebytes + 4);	state[1] = b;
    uint32_t c = load_bigendian_32(statebytes + 8);	state[2] = c;
    uint32_t d = load_bigendian_32(statebytes + 12); state[3] = d;
    uint32_t e = load_bigendian_32(statebytes + 16); state[4] = e;
    uint32_t f = load_bigendian_32(statebytes + 20); state[5] = f;
    uint32_t g = load_bigendian_32(statebytes + 24); state[6] = g;
    uint32_t h = load_bigendian_32(statebytes + 28); state[7] = h;

    while (inlen >= 64) {
        uint32_t w0_t = load_bigendian_32(in + 0);
        uint32_t w1_t = load_bigendian_32(in + 4);
        uint32_t w2_t = load_bigendian_32(in + 8);
        uint32_t w3_t = load_bigendian_32(in + 12);
        uint32_t w4_t = load_bigendian_32(in + 16);
        uint32_t w5_t = load_bigendian_32(in + 20);
        uint32_t w6_t = load_bigendian_32(in + 24);
        uint32_t w7_t = load_bigendian_32(in + 28);
        uint32_t w8_t = load_bigendian_32(in + 32);
        uint32_t w9_t = load_bigendian_32(in + 36);
        uint32_t wa_t = load_bigendian_32(in + 40);
        uint32_t wb_t = load_bigendian_32(in + 44);
        uint32_t wc_t = load_bigendian_32(in + 48);
        uint32_t wd_t = load_bigendian_32(in + 52);
        uint32_t we_t = load_bigendian_32(in + 56);
        uint32_t wf_t = load_bigendian_32(in + 60);

        SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x71374491);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcf);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba5);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x3956c25b);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0x12835b01);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0x243185be);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a7);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174);

        w0_t = SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c1);
        w1_t = SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786);
        w2_t = SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc6);
        w3_t = SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc);
        w4_t = SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f);
        w5_t = SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa);
        w6_t = SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dc);
        w7_t = SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x76f988da);
        w8_t = SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0x983e5152);
        w9_t = SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d);
        wa_t = SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0xb00327c8);
        wb_t = SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7);
        wc_t = SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf3);
        wd_t = SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147);
        we_t = SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0x06ca6351);
        wf_t = SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0x14292967);

        w0_t = SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x27b70a85);
        w1_t = SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x2e1b2138);
        w2_t = SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc);
        w3_t = SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x53380d13);
        w4_t = SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x650a7354);
        w5_t = SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb);
        w6_t = SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e);
        w7_t = SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x92722c85);
        w8_t = SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a1);
        w9_t = SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0xa81a664b);
        wa_t = SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70);
        wb_t = SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a3);
        wc_t = SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0xd192e819);
        wd_t = SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xd6990624);
        we_t = SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0xf40e3585);
        wf_t = SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0x106aa070);

        w0_t = SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116);
        w1_t = SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x1e376c08);
        w2_t = SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x2748774c);
        w3_t = SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5);
        w4_t = SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3);
        w5_t = SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4a);
        w6_t = SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f);
        w7_t = SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3);
        w8_t = SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee);
        w9_t = SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f);
        wa_t = SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0x84c87814);
        wb_t = SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0x8cc70208);
        wc_t = SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0x90befffa);
        wd_t = SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xa4506ceb);
        we_t = SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7);
        wf_t = SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2);

        a += state[0];
        b += state[1];
        c += state[2];
        d += state[3];
        e += state[4];
        f += state[5];
        g += state[6];
        h += state[7];

        state[0] = a;
        state[1] = b;
        state[2] = c;
        state[3] = d;
        state[4] = e;
        state[5] = f;
        state[6] = g;
        state[7] = h;

        in += 64;
        inlen -= 64;
    }
    store_bigendian_32(statebytes + 0, state[0]);
    store_bigendian_32(statebytes + 4, state[1]);
    store_bigendian_32(statebytes + 8, state[2]);
    store_bigendian_32(statebytes + 12, state[3]);
    store_bigendian_32(statebytes + 16, state[4]);
    store_bigendian_32(statebytes + 20, state[5]);
    store_bigendian_32(statebytes + 24, state[6]);
    store_bigendian_32(statebytes + 28, state[7]);
    return inlen;
}
__device__ void sha256_inc_init(uint8_t* state) {
    for (size_t i = 0; i < 32; i++)
        state[i] = iv_256[i];
    for (size_t i = 32; i < 40; i++)
        state[i] = 0;
}
__device__ void sha256_inc_block(uint8_t* state, uint8_t* in, size_t inblocks) {
    uint64_t bytes = load_bigendian_64(state + 32);
    crypto_hashblock_sha256(state, in, 64 * inblocks);
    bytes += 64 * inblocks;
    store_bigendian_64(state + 32, bytes);
}
__device__ void sha256_inc_finalize(uint8_t* out, uint8_t* state, uint8_t* in, size_t inlen) {
    uint8_t padded[128];
    uint64_t bytes = load_bigendian_64(state + 32) + inlen;
    crypto_hashblock_sha256(state, in, inlen);
    in += inlen;
    inlen &= 63;
    in -= inlen;
    for (size_t i = 0; i < inlen; i++)
        padded[i] = in[i];
    padded[inlen] = 0x80;
    if (inlen < 56) {
        for (size_t i = inlen + 1; i < 56; i++)
            padded[i] = 0;
        padded[56] = (uint8_t)(bytes >> 53);
        padded[57] = (uint8_t)(bytes >> 45);
        padded[58] = (uint8_t)(bytes >> 37);
        padded[59] = (uint8_t)(bytes >> 29);
        padded[60] = (uint8_t)(bytes >> 21);
        padded[61] = (uint8_t)(bytes >> 13);
        padded[62] = (uint8_t)(bytes >> 5);
        padded[63] = (uint8_t)(bytes << 3);
        crypto_hashblock_sha256(state, padded, 64);
    }

    else {
        for (size_t i = inlen + 1; i < 120; i++)
            padded[i] = 0;
        padded[120] = (uint8_t)(bytes >> 53);
        padded[121] = (uint8_t)(bytes >> 45);
        padded[122] = (uint8_t)(bytes >> 37);
        padded[123] = (uint8_t)(bytes >> 29);
        padded[124] = (uint8_t)(bytes >> 21);
        padded[125] = (uint8_t)(bytes >> 13);
        padded[126] = (uint8_t)(bytes >> 5);
        padded[127] = (uint8_t)(bytes << 3);
        crypto_hashblock_sha256(state, padded, 128);
    }

    for (size_t i = 0; i < SPX_N; i++)
        out[i] = state[i];
}
__device__ void sha256(uint8_t* out, uint8_t* in, size_t inlen) {
    uint8_t state[40];
    sha256_inc_init(state);
    sha256_inc_finalize(out, state, in, inlen);
}
__device__ void hash_inc_init(uint8_t* state) {
    sha256_inc_init(state);
}
__device__ void hash_inc_block(uint8_t* state, uint8_t* in, size_t inblocks) {
    sha256_inc_block(state, in, inblocks);
}
__device__ void hash_inc_finalize(uint8_t* out, uint8_t* state, uint8_t* in, size_t inlen) {
    sha256_inc_finalize(out, state, in, inlen);
}
__device__ void hash(uint8_t* out, uint8_t* in, size_t inlen) {
    sha256(out, in, inlen);
}

//! GPU FORS iternal function
__device__ void fors_gen_sk(uint8_t* out, uint8_t* key, uint32_t* addr) {
    uint8_t buf[SPX_N + SPX_SHA256_ADDR_BYTES];
    uint8_t outbuf[SPX_N];
    memcpy(buf, key, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_SHA256_ADDR_BYTES);
    hash(outbuf, buf, SPX_N + SPX_SHA256_ADDR_BYTES);
    memcpy(out, outbuf, SPX_N);
}
__device__ void fors_sk_to_leaf(uint8_t* leaf, uint8_t* sk, uint8_t* pub_seed, uint32_t* fors_leaf_addr, uint8_t* state_seed) {
    uint8_t buf[SPX_SHA256_ADDR_BYTES + SPX_N];
    uint8_t outbuf[SPX_SHA256_OUTPUT_BYTES];
    uint8_t hash_state[SPX_SHA256_OUTPUT_BYTES + 8];

    memcpy(hash_state, state_seed, SPX_SHA256_OUTPUT_BYTES + 8);
    memcpy(buf, fors_leaf_addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, sk, SPX_N);

    hash_inc_finalize(outbuf, hash_state, buf, SPX_SHA256_ADDR_BYTES + SPX_N);
    memcpy(leaf, outbuf, SPX_N);
}
__device__ void tree_thash_2depth(uint8_t* out, uint8_t* src0, uint8_t* src1, uint8_t* pub_seed, uint32_t* addr, uint8_t* state_seed) {
    uint8_t buf[SPX_SHA256_ADDR_BYTES + (2 * SPX_N)];
    uint8_t outbuf[SPX_SHA256_OUTPUT_BYTES];
    uint8_t hash_state[SPX_SHA256_OUTPUT_BYTES + 8];

    memcpy(hash_state, state_seed, SPX_SHA256_OUTPUT_BYTES + 8);
    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, src0, SPX_N);
    memcpy(buf + SPX_SHA256_ADDR_BYTES + SPX_N, src1, SPX_N);
    hash_inc_finalize(outbuf, hash_state, buf, SPX_SHA256_ADDR_BYTES + (2 * SPX_N));
    memcpy(out, outbuf, SPX_N);
}
__device__ void final_thash(uint8_t* out, uint8_t* in, uint8_t* pub_seed, uint32_t* addr, uint8_t* state_seed) {
    uint8_t buf[SPX_SHA256_ADDR_BYTES + (SPX_N * SPX_FORS_TREES)];
    uint8_t outbuf[SPX_SHA256_OUTPUT_BYTES];
    uint8_t hash_state[SPX_SHA256_OUTPUT_BYTES + 8];

    memcpy(hash_state, state_seed, SPX_SHA256_OUTPUT_BYTES + 8);
    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, in, SPX_N * SPX_FORS_TREES);

    hash_inc_finalize(outbuf, hash_state, buf, SPX_SHA256_ADDR_BYTES + (SPX_N * SPX_FORS_TREES));
    memcpy(out, outbuf, SPX_N);
}
__device__ void fors_gen_leaf(uint8_t* leaf, uint8_t* sk_seed, uint8_t* pub_seed, uint32_t addr_idx, uint32_t* fors_tree_addr, uint8_t* state_seed) {
    uint32_t fors_leaf_addr[8] = { 0, };
    copy_keypair_addr(fors_leaf_addr, fors_tree_addr);
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    set_tree_index(fors_leaf_addr, addr_idx);
    fors_gen_sk(leaf, sk_seed, fors_leaf_addr);
    fors_sk_to_leaf(leaf, leaf, pub_seed, fors_leaf_addr, state_seed);
}

//! GPU WOTS+ iternal function
__device__ void base_w(uint32_t* output, int out_len, uint8_t* input) {
    int in = 0;
    int out = 0;
    int bits = 0;
    int consumed;
    uint8_t total;
    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= SPX_WOTS_LOGW;
        output[out] = (total >> bits) & (SPX_WOTS_W - 1);
        out++;
    }
}
__device__ void WOTS_checksum(uint32_t* csum_base_w, uint32_t* msg_base_w) {
    unsigned int csum = 0;
    unsigned char csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
    unsigned int i;

    /* Compute checksum. */
    for (i = 0; i < SPX_WOTS_LEN1; i++) {
        csum += SPX_WOTS_W - 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}
__device__ void chain_lengths(uint32_t* lengths, uint8_t* msg) {
    base_w(lengths, SPX_WOTS_LEN1, msg);
    WOTS_checksum(lengths + SPX_WOTS_LEN1, lengths);
}
__device__ void wots_gen_sk(uint8_t* sk, uint8_t* sk_seed, uint32_t* wots_addr) {
    set_hash_addr(wots_addr, 0);

    uint8_t buf[SPX_SHA256_ADDR_BYTES + SPX_N];
    uint8_t outbuf[SPX_SHA256_OUTPUT_BYTES];

    memcpy(buf, sk_seed, SPX_N);
    memcpy(buf + SPX_N, wots_addr, SPX_SHA256_ADDR_BYTES);

    hash(outbuf, buf, SPX_N + SPX_SHA256_ADDR_BYTES);
    memcpy(sk, outbuf, SPX_N);
}
__device__ void wots_chain_thash(uint8_t* out, uint8_t* in, uint8_t* pub_seed, uint8_t* state_seed, uint32_t* addr) {
    uint8_t buf[SPX_N + SPX_SHA256_ADDR_BYTES];
    uint8_t outbuf[SPX_SHA256_OUTPUT_BYTES];
    uint8_t hash_state[SPX_SHA256_OUTPUT_BYTES + 8];

    memcpy(hash_state, state_seed, SPX_SHA256_OUTPUT_BYTES + 8);
    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, in, SPX_N);

    hash_inc_finalize(outbuf, hash_state, buf, SPX_SHA256_ADDR_BYTES + SPX_N);
    memcpy(out, outbuf, SPX_N);
}
__device__ void gen_chain(uint8_t* out, uint8_t* in, uint32_t start, uint32_t steps, uint8_t* pub_seed, uint8_t* state_seed, uint32_t* addr) {
    uint32_t i = 0;
    memcpy(out, in, SPX_N);
    for (i = start; i < (start + steps) && i < SPX_WOTS_W; i++) {
        set_hash_addr(addr, i);
        wots_chain_thash(out, out, pub_seed, state_seed, addr);
    }
}
__device__ void wots_gen_pk(uint8_t* pk, uint8_t* sk_seed, uint8_t* pub_seed, uint8_t* state_seed, uint32_t* addr) {
    uint32_t i = 0;
    for (int i = 0; i < SPX_WOTS_LEN; i++) {
        set_chain_addr(addr, i);
        wots_gen_sk(pk + i * SPX_N, sk_seed, addr);
        gen_chain(pk + i * SPX_N, pk + i * SPX_N, 0, SPX_WOTS_W - 1, pub_seed, state_seed, addr);
    }
}
__device__ void wots_gen_leaf_thash(uint8_t* out, uint8_t* in, uint8_t* pub_seed, uint8_t* state_seed, uint32_t* addr) {
    uint8_t buf[(SPX_WOTS_LEN * SPX_N) + SPX_SHA256_ADDR_BYTES];
    uint8_t outbuf[SPX_SHA256_OUTPUT_BYTES];
    uint8_t hash_state[SPX_SHA256_OUTPUT_BYTES + 8];

    memcpy(hash_state, state_seed, 40);
    memcpy(buf, addr, SPX_SHA256_ADDR_BYTES);
    memcpy(buf + SPX_SHA256_ADDR_BYTES, in, SPX_WOTS_LEN * SPX_N);

    hash_inc_finalize(outbuf, hash_state, buf, 22 + (SPX_WOTS_LEN * SPX_N));
    memcpy(out, outbuf, SPX_N);
}
__device__ void wots_gen_leaf(uint8_t* leaf, uint8_t* sk_seed, uint8_t* pub_seed, uint8_t* state_seed, uint32_t addr_idx, uint32_t* tree_addr) {
    uint8_t pk[SPX_WOTS_BYTES];
    uint32_t wots_addr[8] = { 0, };
    uint32_t wots_pk_addr[8] = { 0, };

    set_type(wots_addr, 0);
    set_type(wots_pk_addr, 1);

    copy_subtree_addr(wots_addr, tree_addr);
    set_keypair_addr(wots_addr, addr_idx);
    wots_gen_pk(pk, sk_seed, pub_seed, state_seed, wots_addr);

    copy_keypair_addr(wots_pk_addr, wots_addr);
    wots_gen_leaf_thash(leaf, pk, pub_seed, state_seed, wots_pk_addr);
}

//! FORS signature
__global__ void fors_sign_latency(uint8_t* sig, uint8_t* roots, uint32_t* indices, uint8_t* sk_seed, uint8_t* pub_seed, uint32_t fors_addr[8], uint8_t* state_seed, uint32_t* lengths) {
    __shared__ uint8_t shared_stack[SPX_N * (1 << SPX_FORS_HEIGHT)];
    uint8_t iternal_pub_seed[SPX_PK_BYTES] = { 0, };
    uint8_t iternal_sk_seed[SPX_SK_BYTES] = { 0, };
    uint8_t iternal_state_seed[SPX_SHA256_OUTPUT_BYTES + 8] = { 0, };

    uint32_t fors_tree_addr[8] = { 0, };
    uint32_t fors_pk_addr[8] = { 0, };
    uint32_t idx_offset = 0;
    uint32_t tree_idx = 0;
    uint32_t leaf_idx = indices[blockIdx.x];
    uint32_t sig_index = (SPX_N * (SPX_FORS_HEIGHT + 1)) * blockIdx.x;

    for (int i = 0; i < SPX_PK_BYTES; i++)
        iternal_pub_seed[i] = pub_seed[i];
    for (int i = 0; i < SPX_SK_BYTES; i++)
        iternal_sk_seed[i] = sk_seed[i];
    for (int i = 0; i < SPX_SHA256_OUTPUT_BYTES + 8; i++)
        iternal_state_seed[i] = state_seed[i];
    __syncthreads();

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);

    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    idx_offset = (blockIdx.x) * (1 << SPX_FORS_HEIGHT);
    if (threadIdx.x == 0) {
        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, leaf_idx + idx_offset);
        fors_gen_sk(sig + sig_index, iternal_sk_seed, fors_tree_addr);
    }

    //! leaf node generation
    fors_gen_leaf(shared_stack + (SPX_N * threadIdx.x), iternal_sk_seed, iternal_pub_seed, threadIdx.x + idx_offset, fors_tree_addr, iternal_state_seed);
    if ((leaf_idx ^ 0x1) == threadIdx.x)
        memcpy(sig + SPX_N + sig_index, shared_stack + (SPX_N * threadIdx.x), SPX_N);
    __syncthreads();

    //! merging process [256 Node   -> 128 Node]
    if (threadIdx.x < 128) {
        set_tree_height(fors_tree_addr, 1);
        set_tree_index(fors_tree_addr, threadIdx.x + (idx_offset >> 1));
        tree_thash_2depth(shared_stack + (2 * SPX_N * threadIdx.x), shared_stack + (2 * SPX_N * threadIdx.x),
            shared_stack + (2 * SPX_N * threadIdx.x) + SPX_N, iternal_pub_seed, fors_tree_addr, iternal_state_seed);
        if (((leaf_idx >> 1) ^ 0x1) == threadIdx.x)
            memcpy(sig + (2 * SPX_N) + sig_index, shared_stack + (2 * SPX_N * threadIdx.x), SPX_N);
    }
    __syncthreads();

    //! merging process [128 Node   -> 64 Node]
    if (threadIdx.x < 64) {
        set_tree_height(fors_tree_addr, 2);
        set_tree_index(fors_tree_addr, threadIdx.x + (idx_offset >> 2));
        tree_thash_2depth(shared_stack + (2 * SPX_N * threadIdx.x) + SPX_N, shared_stack + (4 * SPX_N * threadIdx.x),
            shared_stack + (4 * SPX_N * threadIdx.x) + 2 * SPX_N, iternal_pub_seed, fors_tree_addr, iternal_state_seed);
        if (((leaf_idx >> 2) ^ 0x1) == threadIdx.x)
            memcpy(sig + (3 * SPX_N) + sig_index, shared_stack + (2 * SPX_N * threadIdx.x) + SPX_N, SPX_N);
    }
    __syncthreads();

    //! merging process [64 Node    -> 32 Node]
    if (threadIdx.x < 32) {
        set_tree_height(fors_tree_addr, 3);
        set_tree_index(fors_tree_addr, threadIdx.x + (idx_offset >> 3));
        tree_thash_2depth(shared_stack + (2 * SPX_N * threadIdx.x), shared_stack + (4 * SPX_N * threadIdx.x) + SPX_N,
            shared_stack + (4 * SPX_N * threadIdx.x) + 3 * SPX_N, iternal_pub_seed, fors_tree_addr, iternal_state_seed);
        if (((leaf_idx >> 3) ^ 0x1) == threadIdx.x)
            memcpy(sig + (4 * SPX_N) + sig_index, shared_stack + (2 * SPX_N * threadIdx.x), SPX_N);
    }
    __syncthreads();

    //! merging process [32 Node    -> 16 Node]
    if (threadIdx.x < 16) {
        set_tree_height(fors_tree_addr, 4);
        set_tree_index(fors_tree_addr, threadIdx.x + (idx_offset >> 4));
        tree_thash_2depth(shared_stack + (2 * SPX_N * threadIdx.x) + SPX_N, shared_stack + (4 * SPX_N * threadIdx.x),
            shared_stack + (4 * SPX_N * threadIdx.x) + 2 * SPX_N, iternal_pub_seed, fors_tree_addr, iternal_state_seed);
        if (((leaf_idx >> 4) ^ 0x1) == threadIdx.x)
            memcpy(sig + (5 * SPX_N) + sig_index, shared_stack + (2 * SPX_N * threadIdx.x) + SPX_N, SPX_N);
    }
    __syncthreads();

    //! merging process [16 Node    -> 8 Node]
    if (threadIdx.x < 8) {
        set_tree_height(fors_tree_addr, 5);
        set_tree_index(fors_tree_addr, threadIdx.x + (idx_offset >> 5));
        tree_thash_2depth(shared_stack + (2 * SPX_N * threadIdx.x), shared_stack + (4 * SPX_N * threadIdx.x) + SPX_N,
            shared_stack + (4 * SPX_N * threadIdx.x) + 3 * SPX_N, iternal_pub_seed, fors_tree_addr, iternal_state_seed);
        if (((leaf_idx >> 5) ^ 0x1) == threadIdx.x)
            memcpy(sig + (6 * SPX_N) + sig_index, shared_stack + (2 * SPX_N * threadIdx.x), SPX_N);
    }
    __syncthreads();

    //! merging process [8 Node     -> 4 Node]
    if (threadIdx.x < 4) {
        set_tree_height(fors_tree_addr, 6);
        set_tree_index(fors_tree_addr, threadIdx.x + (idx_offset >> 6));
        tree_thash_2depth(shared_stack + (2 * SPX_N * threadIdx.x) + SPX_N, shared_stack + (4 * SPX_N * threadIdx.x),
            shared_stack + (4 * SPX_N * threadIdx.x) + 2 * SPX_N, iternal_pub_seed, fors_tree_addr, iternal_state_seed);
        if (((leaf_idx >> 6) ^ 0x1) == threadIdx.x)
            memcpy(sig + (7 * SPX_N) + sig_index, shared_stack + (2 * SPX_N * threadIdx.x) + SPX_N, SPX_N);
    }
    __syncthreads();

    //! merging process [4 Node     -> 2 Node]
    if (threadIdx.x < 2) {
        set_tree_height(fors_tree_addr, 7);
        set_tree_index(fors_tree_addr, threadIdx.x + (idx_offset >> 7));
        tree_thash_2depth(shared_stack + (2 * SPX_N * threadIdx.x), shared_stack + (4 * SPX_N * threadIdx.x) + SPX_N,
            shared_stack + (4 * SPX_N * threadIdx.x) + 3 * SPX_N, iternal_pub_seed, fors_tree_addr, iternal_state_seed);
        if (((leaf_idx >> 7) ^ 0x1) == threadIdx.x)
            memcpy(sig + (8 * SPX_N) + sig_index, shared_stack + (2 * SPX_N * threadIdx.x), SPX_N);
    }
    __syncthreads();

    //! merging process [2 Node     -> 1 Node]
    if (threadIdx.x == 0) {
        set_tree_height(fors_tree_addr, 8);
        set_tree_index(fors_tree_addr, idx_offset >> 8);
        tree_thash_2depth(roots + (SPX_N * blockIdx.x), shared_stack, shared_stack + (2 * SPX_N), iternal_pub_seed, fors_tree_addr, iternal_state_seed);
    }
    __syncthreads();

    if (threadIdx.x == 0 && blockIdx.x == 0) {
        uint8_t root[SPX_N];
        final_thash(root, roots, iternal_pub_seed, fors_pk_addr, iternal_state_seed);
        chain_lengths(lengths, root);
    }
}
__global__ void MSS_signature(uint32_t* lengths, uint8_t* sig, uint8_t* sk_seed, uint8_t* pub_seed, uint8_t* state_seed, uint32_t* leaf_idx, uint64_t* tree) {
    uint8_t iternal_pub_seed[SPX_PK_BYTES] = { 0, };
    uint8_t iternal_sk_seed[SPX_SK_BYTES] = { 0, };
    uint8_t iternal_state_seed[SPX_SHA256_OUTPUT_BYTES + 8] = { 0, };
    uint8_t sphincs_root[SPX_N];
    __shared__ uint8_t wots_pk[(1 << SPX_FULL_HEIGHT / SPX_D) * SPX_WOTS_LEN * SPX_N];
    __shared__ uint8_t shared_stack[SPX_N * (1 << (SPX_FULL_HEIGHT / SPX_D))];

    for (int i = 0; i < SPX_PK_BYTES; i++)
        iternal_pub_seed[i] = pub_seed[i];
    for (int i = 0; i < SPX_SK_BYTES; i++)
        iternal_sk_seed[i] = sk_seed[i];
    for (int i = 0; i < SPX_SHA256_OUTPUT_BYTES + 8; i++)
        iternal_state_seed[i] = state_seed[i];
    __syncthreads();

    uint32_t sig_store_index = ((blockIdx.x + 1) * (SPX_WOTS_BYTES + (SPX_N * (SPX_FULL_HEIGHT / SPX_D)))) - (SPX_N * (SPX_FULL_HEIGHT / SPX_D));
    uint32_t sphincs_leaf_idx = leaf_idx[0];
    uint32_t wots_addr[8] = { 0, };
    uint32_t wots_pk_addr[8] = { 0, };
    uint32_t sphincs_idx_offset = 0;
    uint32_t sphincs_tree_addr[8] = { 0, };
    uint64_t sphincs_tree = tree[0];

    for (int i = 0; i < blockIdx.x; i++) {
        sphincs_leaf_idx = (sphincs_tree & ((1 << SPX_TREE_HEIGHT) - 1));
        sphincs_tree = sphincs_tree >> SPX_TREE_HEIGHT;
    }

    set_type(sphincs_tree_addr, 2);
    set_layer_addr(sphincs_tree_addr, blockIdx.x);
    set_tree_addr(sphincs_tree_addr, sphincs_tree);

    //wots_gen_leaf part
    set_type(wots_addr, 0);
    set_type(wots_pk_addr, 1);

    copy_subtree_addr(wots_addr, sphincs_tree_addr);
    set_keypair_addr(wots_addr, threadIdx.x / SPX_WOTS_LEN);

    //wots_gen_pk part
    set_chain_addr(wots_addr, threadIdx.x % SPX_WOTS_LEN);
    wots_gen_sk(sphincs_root, iternal_sk_seed, wots_addr);
    gen_chain(wots_pk + SPX_N * threadIdx.x, sphincs_root, 0, SPX_WOTS_W - 1, iternal_pub_seed, iternal_state_seed, wots_addr);
    __syncthreads();

    if (threadIdx.x < 8) {
        set_keypair_addr(wots_addr, threadIdx.x + sphincs_idx_offset);
        copy_keypair_addr(wots_pk_addr, wots_addr);
        wots_gen_leaf_thash(shared_stack + SPX_N * threadIdx.x, wots_pk + (SPX_WOTS_LEN * SPX_N * threadIdx.x), pub_seed, state_seed, wots_pk_addr);
        if ((sphincs_leaf_idx ^ 0x1) == threadIdx.x) {
            memcpy(sig + sig_store_index, shared_stack + (SPX_N * threadIdx.x), SPX_N);
        }
    }
    __syncthreads();

    //! merging process [8 Node -> 4 Node]
    if (threadIdx.x < 4) {
        set_tree_height(sphincs_tree_addr, 1);
        set_tree_index(sphincs_tree_addr, threadIdx.x + (sphincs_idx_offset >> 1));
        tree_thash_2depth(shared_stack + (2 * SPX_N * threadIdx.x), shared_stack + (2 * SPX_N * threadIdx.x),
            shared_stack + (2 * SPX_N * threadIdx.x) + SPX_N, iternal_pub_seed, sphincs_tree_addr, iternal_state_seed);
        if (((sphincs_leaf_idx >> 1) ^ 0x1) == threadIdx.x)
            memcpy(sig + sig_store_index + SPX_N, shared_stack + (2 * SPX_N * threadIdx.x), SPX_N);
    }
    __syncthreads();

    //! merging process [4 Node -> 2 Node]
    if (threadIdx.x < 2) {
        set_tree_height(sphincs_tree_addr, 2);
        set_tree_index(sphincs_tree_addr, threadIdx.x + (sphincs_idx_offset >> 2));
        tree_thash_2depth(shared_stack + (2 * SPX_N * threadIdx.x) + SPX_N, shared_stack + (4 * SPX_N * threadIdx.x),
            shared_stack + (4 * SPX_N * threadIdx.x) + 2 * SPX_N, iternal_pub_seed, sphincs_tree_addr, iternal_state_seed);
        if (((sphincs_leaf_idx >> 2) ^ 0x1) == threadIdx.x)
            memcpy(sig + sig_store_index + 2 * SPX_N, shared_stack + (2 * SPX_N * threadIdx.x + SPX_N), SPX_N);
    }
    __syncthreads();

    //! merging process [2 Node -> 1 Node]
    if (threadIdx.x == 0) {
        set_tree_height(sphincs_tree_addr, 3);
        set_tree_index(sphincs_tree_addr, (sphincs_idx_offset >> 3));
        tree_thash_2depth(sphincs_root, shared_stack + SPX_N, shared_stack + (3 * SPX_N), iternal_pub_seed, sphincs_tree_addr, iternal_state_seed);
        chain_lengths(lengths + SPX_WOTS_LEN * blockIdx.x, sphincs_root);
    }
}
__global__ void wots_sign(uint8_t* sig, uint32_t* lengths, uint8_t* sk_seed, uint8_t* pub_seed, uint8_t* state_seed, uint32_t* leaf_idx, uint64_t* tree) {
    uint8_t hash_temp[SPX_SHA256_OUTPUT_BYTES] = { 0, };
    uint8_t buffer[SPX_SHA256_OUTPUT_BYTES] = { 0, };
    uint8_t iternal_pub_seed[SPX_PK_BYTES];
    uint8_t iternal_sk_seed[SPX_SK_BYTES];
    uint8_t iternal_state_seed[SPX_SHA256_OUTPUT_BYTES + 8];
    uint32_t sphincs_tree_addr[8] = { 0, };
    uint32_t sphincs_wots_addr[8] = { 0, };
    uint32_t sig_store_index = (blockIdx.x) * (SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N);
    uint64_t sphincs_tree = 0;
    uint64_t sphincs_leaf_idx = 0;

    //parameter setting
    sphincs_tree = tree[0];
    sphincs_leaf_idx = leaf_idx[0];

    for (int i = 0; i < blockIdx.x; i++) {
        sphincs_leaf_idx = (sphincs_tree & ((1 << SPX_TREE_HEIGHT) - 1));
        sphincs_tree = sphincs_tree >> SPX_TREE_HEIGHT;
    }

    for (int i = 0; i < SPX_PK_BYTES; i++)
        iternal_pub_seed[i] = pub_seed[i];
    for (int i = 0; i < SPX_SK_BYTES; i++)
        iternal_sk_seed[i] = sk_seed[i];
    for (int i = 0; i < SPX_SHA256_OUTPUT_BYTES + 8; i++)
        iternal_state_seed[i] = state_seed[i];
    __syncthreads();
    set_type(sphincs_tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_layer_addr(sphincs_tree_addr, blockIdx.x);
    set_tree_addr(sphincs_tree_addr, sphincs_tree);
    copy_subtree_addr(sphincs_wots_addr, sphincs_tree_addr);
    set_keypair_addr(sphincs_wots_addr, sphincs_leaf_idx);

    set_chain_addr(sphincs_wots_addr, threadIdx.x);
    wots_gen_sk(hash_temp, iternal_sk_seed, sphincs_wots_addr);
    gen_chain(buffer, hash_temp, 0, lengths[(SPX_WOTS_LEN * blockIdx.x) + threadIdx.x], iternal_pub_seed, iternal_state_seed, sphincs_wots_addr);
    memcpy(sig + sig_store_index + (SPX_N * threadIdx.x), buffer, SPX_N);

}

__device__ void AES256_keyscheme(uint8_t* userKey, uint32_t* rk) {
    int i = 0;
    uint32_t temp = 0;
    for (i = 0; i < 8; i++) {
        rk[i] = (userKey[4 * i] << 24) | (userKey[4 * i + 1] << 16) | (userKey[4 * i + 2] << 8) | (userKey[4 * i + 3]);
    }
    i = 8;
    while (i < 4 * 15) {
        temp = rk[i - 1];
        if (i % 8 == 0) {
            temp = ((shared_Te3[((rk[i - 1] >> 16) & 0xff)] & 0xff000000) | (shared_Te3[((rk[i - 1] >> 8) & 0xff)] & 0x00ff0000) | (shared_Te1[((rk[i - 1]) & 0xff)] & 0x0000ff00) | (shared_Te1[((rk[i - 1] >> 24) & 0xff)] & 0x000000ff)) ^ rcon[i / 8];
        }
        if (i % 8 == 4) {
            temp = ((shared_Te3[((rk[i - 1] >> 24) & 0xff)] & 0xff000000) | (shared_Te3[((rk[i - 1] >> 16) & 0xff)] & 0x00ff0000) | (shared_Te1[((rk[i - 1] >> 8) & 0xff)] & 0x0000ff00) | (shared_Te1[((rk[i - 1]) & 0xff)] & 0x000000ff));
        }
        rk[i] = rk[i - 8] ^ temp;
        i++;
    }
}
__device__ void AES256_ECB(uint32_t* rk, uint8_t* pt, uint8_t* ct) {
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
    s0 = GPU_ENDIAN_CHANGE(*(uint32_t*)(pt + 0));
    s1 = GPU_ENDIAN_CHANGE(*(uint32_t*)(pt + 4));
    s2 = GPU_ENDIAN_CHANGE(*(uint32_t*)(pt + 8));
    s3 = GPU_ENDIAN_CHANGE(*(uint32_t*)(pt + 12));

    /* round 0: */
    s0 = s0 ^ rk[0];
    s1 = s1 ^ rk[1];
    s2 = s2 ^ rk[2];
    s3 = s3 ^ rk[3];

    /* round 1: */
    t0 = shared_Te0[s0 >> 24] ^ shared_Te1[(s1 >> 16) & 0xff] ^ shared_Te2[(s2 >> 8) & 0xff] ^ shared_Te3[s3 & 0xff] ^ rk[4];
    t1 = shared_Te0[s1 >> 24] ^ shared_Te1[(s2 >> 16) & 0xff] ^ shared_Te2[(s3 >> 8) & 0xff] ^ shared_Te3[s0 & 0xff] ^ rk[5];
    t2 = shared_Te0[s2 >> 24] ^ shared_Te1[(s3 >> 16) & 0xff] ^ shared_Te2[(s0 >> 8) & 0xff] ^ shared_Te3[s1 & 0xff] ^ rk[6];
    t3 = shared_Te0[s3 >> 24] ^ shared_Te1[(s0 >> 16) & 0xff] ^ shared_Te2[(s1 >> 8) & 0xff] ^ shared_Te3[s2 & 0xff] ^ rk[7];

    /* round 2: */
    s0 = shared_Te0[t0 >> 24] ^ shared_Te1[(t1 >> 16) & 0xff] ^ shared_Te2[(t2 >> 8) & 0xff] ^ shared_Te3[t3 & 0xff] ^ rk[8];
    s1 = shared_Te0[t1 >> 24] ^ shared_Te1[(t2 >> 16) & 0xff] ^ shared_Te2[(t3 >> 8) & 0xff] ^ shared_Te3[t0 & 0xff] ^ rk[9];
    s2 = shared_Te0[t2 >> 24] ^ shared_Te1[(t3 >> 16) & 0xff] ^ shared_Te2[(t0 >> 8) & 0xff] ^ shared_Te3[t1 & 0xff] ^ rk[10];
    s3 = shared_Te0[t3 >> 24] ^ shared_Te1[(t0 >> 16) & 0xff] ^ shared_Te2[(t1 >> 8) & 0xff] ^ shared_Te3[t2 & 0xff] ^ rk[11];

    /* round 3: */
    t0 = shared_Te0[s0 >> 24] ^ shared_Te1[(s1 >> 16) & 0xff] ^ shared_Te2[(s2 >> 8) & 0xff] ^ shared_Te3[s3 & 0xff] ^ rk[12];
    t1 = shared_Te0[s1 >> 24] ^ shared_Te1[(s2 >> 16) & 0xff] ^ shared_Te2[(s3 >> 8) & 0xff] ^ shared_Te3[s0 & 0xff] ^ rk[13];
    t2 = shared_Te0[s2 >> 24] ^ shared_Te1[(s3 >> 16) & 0xff] ^ shared_Te2[(s0 >> 8) & 0xff] ^ shared_Te3[s1 & 0xff] ^ rk[14];
    t3 = shared_Te0[s3 >> 24] ^ shared_Te1[(s0 >> 16) & 0xff] ^ shared_Te2[(s1 >> 8) & 0xff] ^ shared_Te3[s2 & 0xff] ^ rk[15];

    /* round 4: */
    s0 = shared_Te0[t0 >> 24] ^ shared_Te1[(t1 >> 16) & 0xff] ^ shared_Te2[(t2 >> 8) & 0xff] ^ shared_Te3[t3 & 0xff] ^ rk[16];
    s1 = shared_Te0[t1 >> 24] ^ shared_Te1[(t2 >> 16) & 0xff] ^ shared_Te2[(t3 >> 8) & 0xff] ^ shared_Te3[t0 & 0xff] ^ rk[17];
    s2 = shared_Te0[t2 >> 24] ^ shared_Te1[(t3 >> 16) & 0xff] ^ shared_Te2[(t0 >> 8) & 0xff] ^ shared_Te3[t1 & 0xff] ^ rk[18];
    s3 = shared_Te0[t3 >> 24] ^ shared_Te1[(t0 >> 16) & 0xff] ^ shared_Te2[(t1 >> 8) & 0xff] ^ shared_Te3[t2 & 0xff] ^ rk[19];

    /* round 5: */
    t0 = shared_Te0[s0 >> 24] ^ shared_Te1[(s1 >> 16) & 0xff] ^ shared_Te2[(s2 >> 8) & 0xff] ^ shared_Te3[s3 & 0xff] ^ rk[20];
    t1 = shared_Te0[s1 >> 24] ^ shared_Te1[(s2 >> 16) & 0xff] ^ shared_Te2[(s3 >> 8) & 0xff] ^ shared_Te3[s0 & 0xff] ^ rk[21];
    t2 = shared_Te0[s2 >> 24] ^ shared_Te1[(s3 >> 16) & 0xff] ^ shared_Te2[(s0 >> 8) & 0xff] ^ shared_Te3[s1 & 0xff] ^ rk[22];
    t3 = shared_Te0[s3 >> 24] ^ shared_Te1[(s0 >> 16) & 0xff] ^ shared_Te2[(s1 >> 8) & 0xff] ^ shared_Te3[s2 & 0xff] ^ rk[23];

    /* round 6: */
    s0 = shared_Te0[t0 >> 24] ^ shared_Te1[(t1 >> 16) & 0xff] ^ shared_Te2[(t2 >> 8) & 0xff] ^ shared_Te3[t3 & 0xff] ^ rk[24];
    s1 = shared_Te0[t1 >> 24] ^ shared_Te1[(t2 >> 16) & 0xff] ^ shared_Te2[(t3 >> 8) & 0xff] ^ shared_Te3[t0 & 0xff] ^ rk[25];
    s2 = shared_Te0[t2 >> 24] ^ shared_Te1[(t3 >> 16) & 0xff] ^ shared_Te2[(t0 >> 8) & 0xff] ^ shared_Te3[t1 & 0xff] ^ rk[26];
    s3 = shared_Te0[t3 >> 24] ^ shared_Te1[(t0 >> 16) & 0xff] ^ shared_Te2[(t1 >> 8) & 0xff] ^ shared_Te3[t2 & 0xff] ^ rk[27];

    /* round 7: */
    t0 = shared_Te0[s0 >> 24] ^ shared_Te1[(s1 >> 16) & 0xff] ^ shared_Te2[(s2 >> 8) & 0xff] ^ shared_Te3[s3 & 0xff] ^ rk[28];
    t1 = shared_Te0[s1 >> 24] ^ shared_Te1[(s2 >> 16) & 0xff] ^ shared_Te2[(s3 >> 8) & 0xff] ^ shared_Te3[s0 & 0xff] ^ rk[29];
    t2 = shared_Te0[s2 >> 24] ^ shared_Te1[(s3 >> 16) & 0xff] ^ shared_Te2[(s0 >> 8) & 0xff] ^ shared_Te3[s1 & 0xff] ^ rk[30];
    t3 = shared_Te0[s3 >> 24] ^ shared_Te1[(s0 >> 16) & 0xff] ^ shared_Te2[(s1 >> 8) & 0xff] ^ shared_Te3[s2 & 0xff] ^ rk[31];

    /* round 8: */
    s0 = shared_Te0[t0 >> 24] ^ shared_Te1[(t1 >> 16) & 0xff] ^ shared_Te2[(t2 >> 8) & 0xff] ^ shared_Te3[t3 & 0xff] ^ rk[32];
    s1 = shared_Te0[t1 >> 24] ^ shared_Te1[(t2 >> 16) & 0xff] ^ shared_Te2[(t3 >> 8) & 0xff] ^ shared_Te3[t0 & 0xff] ^ rk[33];
    s2 = shared_Te0[t2 >> 24] ^ shared_Te1[(t3 >> 16) & 0xff] ^ shared_Te2[(t0 >> 8) & 0xff] ^ shared_Te3[t1 & 0xff] ^ rk[34];
    s3 = shared_Te0[t3 >> 24] ^ shared_Te1[(t0 >> 16) & 0xff] ^ shared_Te2[(t1 >> 8) & 0xff] ^ shared_Te3[t2 & 0xff] ^ rk[35];

    /* round 9: */
    t0 = shared_Te0[s0 >> 24] ^ shared_Te1[(s1 >> 16) & 0xff] ^ shared_Te2[(s2 >> 8) & 0xff] ^ shared_Te3[s3 & 0xff] ^ rk[36];
    t1 = shared_Te0[s1 >> 24] ^ shared_Te1[(s2 >> 16) & 0xff] ^ shared_Te2[(s3 >> 8) & 0xff] ^ shared_Te3[s0 & 0xff] ^ rk[37];
    t2 = shared_Te0[s2 >> 24] ^ shared_Te1[(s3 >> 16) & 0xff] ^ shared_Te2[(s0 >> 8) & 0xff] ^ shared_Te3[s1 & 0xff] ^ rk[38];
    t3 = shared_Te0[s3 >> 24] ^ shared_Te1[(s0 >> 16) & 0xff] ^ shared_Te2[(s1 >> 8) & 0xff] ^ shared_Te3[s2 & 0xff] ^ rk[39];

    /* round 10: */
    s0 = shared_Te0[t0 >> 24] ^ shared_Te1[(t1 >> 16) & 0xff] ^ shared_Te2[(t2 >> 8) & 0xff] ^ shared_Te3[t3 & 0xff] ^ rk[40];
    s1 = shared_Te0[t1 >> 24] ^ shared_Te1[(t2 >> 16) & 0xff] ^ shared_Te2[(t3 >> 8) & 0xff] ^ shared_Te3[t0 & 0xff] ^ rk[41];
    s2 = shared_Te0[t2 >> 24] ^ shared_Te1[(t3 >> 16) & 0xff] ^ shared_Te2[(t0 >> 8) & 0xff] ^ shared_Te3[t1 & 0xff] ^ rk[42];
    s3 = shared_Te0[t3 >> 24] ^ shared_Te1[(t0 >> 16) & 0xff] ^ shared_Te2[(t1 >> 8) & 0xff] ^ shared_Te3[t2 & 0xff] ^ rk[43];

    /* round 11: */
    t0 = shared_Te0[s0 >> 24] ^ shared_Te1[(s1 >> 16) & 0xff] ^ shared_Te2[(s2 >> 8) & 0xff] ^ shared_Te3[s3 & 0xff] ^ rk[44];
    t1 = shared_Te0[s1 >> 24] ^ shared_Te1[(s2 >> 16) & 0xff] ^ shared_Te2[(s3 >> 8) & 0xff] ^ shared_Te3[s0 & 0xff] ^ rk[45];
    t2 = shared_Te0[s2 >> 24] ^ shared_Te1[(s3 >> 16) & 0xff] ^ shared_Te2[(s0 >> 8) & 0xff] ^ shared_Te3[s1 & 0xff] ^ rk[46];
    t3 = shared_Te0[s3 >> 24] ^ shared_Te1[(s0 >> 16) & 0xff] ^ shared_Te2[(s1 >> 8) & 0xff] ^ shared_Te3[s2 & 0xff] ^ rk[47];

    /* round 12: */
    s0 = shared_Te0[t0 >> 24] ^ shared_Te1[(t1 >> 16) & 0xff] ^ shared_Te2[(t2 >> 8) & 0xff] ^ shared_Te3[t3 & 0xff] ^ rk[48];
    s1 = shared_Te0[t1 >> 24] ^ shared_Te1[(t2 >> 16) & 0xff] ^ shared_Te2[(t3 >> 8) & 0xff] ^ shared_Te3[t0 & 0xff] ^ rk[49];
    s2 = shared_Te0[t2 >> 24] ^ shared_Te1[(t3 >> 16) & 0xff] ^ shared_Te2[(t0 >> 8) & 0xff] ^ shared_Te3[t1 & 0xff] ^ rk[50];
    s3 = shared_Te0[t3 >> 24] ^ shared_Te1[(t0 >> 16) & 0xff] ^ shared_Te2[(t1 >> 8) & 0xff] ^ shared_Te3[t2 & 0xff] ^ rk[51];

    /* round 13: */
    t0 = shared_Te0[s0 >> 24] ^ shared_Te1[(s1 >> 16) & 0xff] ^ shared_Te2[(s2 >> 8) & 0xff] ^ shared_Te3[s3 & 0xff] ^ rk[52];
    t1 = shared_Te0[s1 >> 24] ^ shared_Te1[(s2 >> 16) & 0xff] ^ shared_Te2[(s3 >> 8) & 0xff] ^ shared_Te3[s0 & 0xff] ^ rk[53];
    t2 = shared_Te0[s2 >> 24] ^ shared_Te1[(s3 >> 16) & 0xff] ^ shared_Te2[(s0 >> 8) & 0xff] ^ shared_Te3[s1 & 0xff] ^ rk[54];
    t3 = shared_Te0[s3 >> 24] ^ shared_Te1[(s0 >> 16) & 0xff] ^ shared_Te2[(s1 >> 8) & 0xff] ^ shared_Te3[s2 & 0xff] ^ rk[55];

    /* round 14: */
    s0 =
        (shared_Te2[(t0 >> 24)] & 0xff000000) ^
        (shared_Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^
        (shared_Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^
        (shared_Te1[(t3) & 0xff] & 0x000000ff) ^
        rk[56];
    s1 =
        (shared_Te2[(t1 >> 24)] & 0xff000000) ^
        (shared_Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^
        (shared_Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^
        (shared_Te1[(t0) & 0xff] & 0x000000ff) ^
        rk[57];
    s2 =
        (shared_Te2[(t2 >> 24)] & 0xff000000) ^
        (shared_Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^
        (shared_Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^
        (shared_Te1[(t1) & 0xff] & 0x000000ff) ^
        rk[58];
    s3 =
        (shared_Te2[(t3 >> 24)] & 0xff000000) ^
        (shared_Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^
        (shared_Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^
        (shared_Te1[(t2) & 0xff] & 0x000000ff) ^
        rk[59];

    ct[0] = (s0 >> 24) & 0xff;
    ct[1] = (s0 >> 16) & 0xff;
    ct[2] = (s0 >> 8) & 0xff;
    ct[3] = (s0 >> 0) & 0xff;

    ct[4] = (s1 >> 24) & 0xff;
    ct[5] = (s1 >> 16) & 0xff;
    ct[6] = (s1 >> 8) & 0xff;
    ct[7] = (s1 >> 0) & 0xff;

    ct[8] = (s2 >> 24) & 0xff;
    ct[9] = (s2 >> 16) & 0xff;
    ct[10] = (s2 >> 8) & 0xff;
    ct[11] = (s2 >> 0) & 0xff;

    ct[12] = (s3 >> 24) & 0xff;
    ct[13] = (s3 >> 16) & 0xff;
    ct[14] = (s3 >> 8) & 0xff;
    ct[15] = (s3 >> 0) & 0xff;
}
__device__ void AES256_CTR_DRBG_Update(uint8_t* provided_data, uint32_t* key, uint8_t* V) {
    uint8_t temp[48] = { 0, };
    for (int i = 0; i < 3; i++) {
        //increment V
        for (int j = 15; j >= 0; j--) {
            if (V[j] == 0xff)
                V[j] = 0x00;
            else {
                V[j]++;
                break;
            }
        }
        AES256_ECB(key, V, temp + 16 * i);
    }
    if (provided_data != NULL) {
        for (int i = 0; i < 48; i++)
            temp[i] ^= provided_data[i];
    }
    AES256_keyscheme(temp, key);
    memcpy(V, temp + 32, 16);
}
__device__ void randombytes_init(AES256_CTR_DRBG_struct* info, uint8_t* entropy_input) {
    uint8_t seed_material[48];
    memcpy(seed_material, entropy_input, 48);
    memset(info->Key, 0, 32);
    memset(info->V, 0, 16);
    AES256_keyscheme(info->Key, info->rk);
    AES256_CTR_DRBG_Update(seed_material, info->rk, info->V);
    info->reseed_counter = 1;
}
__device__ void randombytes(AES256_CTR_DRBG_struct* info, uint8_t* src, uint64_t xlen) {
    uint8_t block[16] = { 0, };
    int i = 0;

    while (xlen > 0) {
        for (int j = 15; j >= 0; j--) {
            if (info->V[j] == 0xff)
                info->V[j] = 0x00;
            else {
                info->V[j]++;
                break;
            }
        }
        AES256_ECB(info->rk, info->V, block);
        if (xlen > 15) {
            memcpy(src + i, block, 16);
            i += 16;
            xlen -= 16;
        }
        else {
            memcpy(src + i, block, xlen);
            xlen = 0;
        }
    }
    AES256_CTR_DRBG_Update(NULL, info->rk, info->V);

}
__global__ void crypto_sign_keypair(uint8_t* iternal_seed, uint8_t* pk, uint8_t* sk, uint8_t* state) {
    __shared__ uint8_t seed[CRYPTO_SEEDBYTES];
    __shared__ uint8_t wots_pk[(1 << SPX_FULL_HEIGHT / SPX_D) * SPX_WOTS_LEN * SPX_N];
    __shared__ uint8_t shared_stack[SPX_N * (1 << (SPX_FULL_HEIGHT / SPX_D))];

    if (threadIdx.x == 0) {
        for (int i = 0; i < CRYPTO_SEEDBYTES; i++)
            seed[i] = iternal_seed[i];
    }
    __syncthreads();

    //crypto_sign_seed_keypair part
    uint32_t top_tree_addr[8] = { 0, };
    uint32_t wots_addr[8] = { 0, };
    uint32_t wots_pk_addr[8] = { 0, };

    uint8_t iternal_pk[2 * SPX_N];
    uint8_t iternal_sk[4 * SPX_N];
    uint8_t iternal_state[SPX_SHA256_OUTPUT_BYTES + 8];
    uint8_t iternal_block[SPX_SHA256_BLOCK_BYTES];
    uint8_t iternal_temp[SPX_N];

    set_layer_addr(top_tree_addr, SPX_D - 1);
    set_type(top_tree_addr, SPX_ADDR_TYPE_HASHTREE);

    for (int i = 0; i < CRYPTO_SEEDBYTES; i++)
        iternal_sk[i] = seed[i];
    for (int i = 0; i < SPX_N; i++)
        iternal_pk[i] = seed[i];

    //initialize_hash_function
    for (int i = 0; i < SPX_N; i++)
        iternal_block[i] = iternal_pk[i];
    for (int i = SPX_N; i < SPX_SHA256_BLOCK_BYTES; i++)
        iternal_block[i] = 0;

    sha256_inc_init(iternal_state);
    sha256_inc_block(iternal_state, iternal_block, 1);

    //wots_gen_leaf parallel
    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    copy_subtree_addr(wots_addr, top_tree_addr);
    set_keypair_addr(wots_addr, threadIdx.x / SPX_WOTS_LEN);

    //wots_gen_pk part
    set_chain_addr(wots_addr, threadIdx.x % SPX_WOTS_LEN);
    wots_gen_sk(iternal_temp, iternal_sk, wots_addr);
    gen_chain(wots_pk + SPX_N * threadIdx.x, iternal_temp, 0, SPX_WOTS_W - 1, iternal_pk, iternal_sk, wots_addr);
    __syncthreads();

    if (threadIdx.x < 8) {
        set_keypair_addr(wots_addr, threadIdx.x);
        copy_keypair_addr(wots_pk_addr, wots_addr);
        wots_gen_leaf_thash(shared_stack + SPX_N * threadIdx.x, wots_pk + (SPX_WOTS_LEN * SPX_N * threadIdx.x), iternal_pk, iternal_state, wots_pk_addr);
    }
    __syncthreads();


    //! merging process [8 Node -> 4 Node]
    if (threadIdx.x < 4) {
        set_tree_height(top_tree_addr, 1);
        set_tree_index(top_tree_addr, threadIdx.x);
        tree_thash_2depth(shared_stack + (2 * SPX_N * threadIdx.x), shared_stack + (2 * SPX_N * threadIdx.x),
            shared_stack + (2 * SPX_N * threadIdx.x) + SPX_N, iternal_pk, top_tree_addr, iternal_state);
    }
    __syncthreads();

    //! merging process [4 Node -> 2 Node]
    if (threadIdx.x < 2) {
        set_tree_height(top_tree_addr, 2);
        set_tree_index(top_tree_addr, threadIdx.x);
        tree_thash_2depth(shared_stack + (2 * SPX_N * threadIdx.x) + SPX_N, shared_stack + (4 * SPX_N * threadIdx.x),
            shared_stack + (4 * SPX_N * threadIdx.x) + 2 * SPX_N, iternal_pk, top_tree_addr, iternal_state);
    }
    __syncthreads();

    if (threadIdx.x == 0) {
        set_tree_height(top_tree_addr, 3);
        set_tree_index(top_tree_addr, 0);
        tree_thash_2depth(iternal_sk + 3 * SPX_N, shared_stack + SPX_N, shared_stack + (3 * SPX_N), iternal_pk, top_tree_addr, iternal_state);

        for (int i = 0; i < SPX_PK_BYTES; i++)
            pk[i + (blockIdx.x * SPX_PK_BYTES)] = iternal_pk[i];
        for (int i = 0; i < SPX_SK_BYTES; i++)
            sk[i + (blockIdx.x * SPX_SK_BYTES)] = iternal_sk[i];
        for (int i = 0; i < SPX_SHA256_OUTPUT_BYTES + 8; i++) {
            state[i + (blockIdx.x * (SPX_SHA256_OUTPUT_BYTES + 8))] = iternal_state[i];

        }
    }
}

void crypto_sign_keypair_test(int blocksize) {
    uint8_t cpu_seed[CRYPTO_SEEDBYTES] = { 0, };

    uint8_t* gpu_pk = NULL;
    uint8_t* gpu_sk = NULL;
    uint8_t* gpu_seed = NULL;
    uint8_t* gpu_state = NULL;
    AES256_CTR_DRBG_struct* gpu_info = NULL;
    cudaMalloc((void**)&gpu_pk, SPX_PK_BYTES * blocksize);
    cudaMalloc((void**)&gpu_sk, SPX_SK_BYTES * blocksize);
    cudaMalloc((void**)&gpu_state, (SPX_SHA256_OUTPUT_BYTES + 8) * blocksize);
    cudaMalloc((void**)&gpu_seed, CRYPTO_SEEDBYTES);
    cudaMalloc((void**)&gpu_info, sizeof(AES256_CTR_DRBG_struct));
    cudaMemcpy(gpu_seed, cpu_seed, CRYPTO_SEEDBYTES, cudaMemcpyHostToDevice);

    float elapsed_time_ms = 0.0f;
    cudaEvent_t start, stop;
    cudaError_t err;

    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);
    for (int i = 0; i < 10000; i++) {
        crypto_sign_keypair << <blocksize, (1 << (SPX_FULL_HEIGHT / SPX_D))* SPX_WOTS_LEN >> > (gpu_seed, gpu_pk, gpu_sk, gpu_state);
    }
    cudaEventRecord(stop, 0);
    cudaDeviceSynchronize();
    cudaEventSynchronize(start);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&elapsed_time_ms, start, stop);
    elapsed_time_ms /= 10000;
    printf("sign_keypair = %4.2f ms\n", elapsed_time_ms);
    elapsed_time_ms = 1000 / elapsed_time_ms;
    elapsed_time_ms = elapsed_time_ms * blocksize;
    printf("sign_keypair = %4.2f ms\n", elapsed_time_ms);

}

int crypto_sign_signature_security_level_3(uint8_t* sig, size_t* siglen, uint8_t* m, size_t mlen, uint8_t* sk) {
    uint8_t* sk_seed = sk;
    uint8_t* sk_prf = sk + SPX_N;
    uint8_t* pk = sk + (2 * SPX_N);
    uint8_t* pub_seed = pk;
    uint8_t state_seed[SPX_SHA256_OUTPUT_BYTES + 8];
    uint8_t optrand[SPX_N];
    uint8_t mhash[SPX_FORS_MSG_BYTES];
    uint8_t root[SPX_N];
    uint32_t idx_leaf = 0;
    uint32_t indices[SPX_FORS_TREES] = { 0, };
    uint32_t wots_addr[8] = { 0, };
    uint32_t tree_addr[8] = { 0, };
    uint64_t i = 0;
    uint64_t tree = 0;
    uint64_t sig_index = 0;
    CPU_hash_initialize_hash_function(pub_seed, sk_seed, state_seed);
    CPU_randombytes(optrand, SPX_N);
    CPU_gen_message_random(sig, sk_prf, optrand, m, mlen);
    CPU_hash_message(mhash, &tree, &idx_leaf, sig + sig_index, pk, m, mlen); sig_index += SPX_N;
    CPU_set_tree_addr(wots_addr, tree);
    CPU_set_keypair_addr(wots_addr, idx_leaf);
    CPU_message_to_indices(indices, mhash);

    //! GPU FORS Params set
    uint8_t* gpu_fors_sig = NULL;
    uint8_t* gpu_root = NULL;
    uint8_t* gpu_sk_seed = NULL;
    uint8_t* gpu_pub_seed = NULL;
    uint8_t* gpu_state_seed = NULL;
    uint32_t* gpu_wots_addr = NULL;
    uint32_t* gpu_indices = NULL;
    uint32_t* gpu_lengths = NULL;

    //! GPU WOTS+ Params set
    uint8_t* gpu_wots_sig = NULL;
    uint32_t* gpu_idx_leaf = NULL;
    uint64_t* gpu_tree = NULL;

    //! GPU FORS Malloc & Memcopy Copy
    cudaMalloc((void**)&gpu_fors_sig, sizeof(uint8_t) * SPX_FORS_BYTES);
    cudaMalloc((void**)&gpu_root, SPX_FORS_TREES * sizeof(uint8_t) * SPX_N);
    cudaMalloc((void**)&gpu_sk_seed, sizeof(uint8_t) * SPX_SK_BYTES);
    cudaMalloc((void**)&gpu_pub_seed, sizeof(uint8_t) * SPX_PK_BYTES);
    cudaMalloc((void**)&gpu_state_seed, sizeof(uint8_t) * 40);
    cudaMalloc((void**)&gpu_wots_addr, sizeof(uint32_t) * 8);
    cudaMalloc((void**)&gpu_indices, sizeof(uint32_t) * SPX_FORS_TREES);
    cudaMalloc((void**)&gpu_lengths, sizeof(uint32_t) * SPX_WOTS_LEN * (SPX_D + 1));

    cudaMemcpy(gpu_indices, indices, sizeof(uint32_t) * SPX_FORS_TREES, cudaMemcpyHostToDevice);
    cudaMemcpy(gpu_sk_seed, sk_seed, sizeof(uint8_t) * SPX_SK_BYTES, cudaMemcpyHostToDevice);
    cudaMemcpy(gpu_pub_seed, pub_seed, sizeof(uint8_t) * SPX_PK_BYTES, cudaMemcpyHostToDevice);
    cudaMemcpy(gpu_wots_addr, wots_addr, sizeof(uint32_t) * 8, cudaMemcpyHostToDevice);
    cudaMemcpy(gpu_state_seed, state_seed, sizeof(uint8_t) * 40, cudaMemcpyHostToDevice);

    //! GPU WOTS+ Malloc & Memory Copy
    cudaMalloc((void**)&gpu_idx_leaf, sizeof(uint32_t));
    cudaMalloc((void**)&gpu_tree, sizeof(uint64_t));
    cudaMalloc((void**)&gpu_wots_sig, SPX_D * (SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N));
    cudaMemcpy(gpu_idx_leaf, &idx_leaf, sizeof(uint32_t), cudaMemcpyHostToDevice);
    cudaMemcpy(gpu_tree, &tree, sizeof(uint64_t), cudaMemcpyHostToDevice);

    float elapsed_time_ms = 0.0f;
    cudaEvent_t start, stop;
    cudaError_t err;

    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);
    for (int i = 0; i < 10000; i++) {
        fors_sign_latency << <SPX_FORS_TREES, (1 << SPX_FORS_HEIGHT) >> > (gpu_fors_sig, gpu_root, gpu_indices, gpu_sk_seed, gpu_pub_seed, gpu_wots_addr, gpu_state_seed, gpu_lengths);
        MSS_signature << < SPX_D, SPX_WOTS_LEN* (1 << (SPX_FULL_HEIGHT / SPX_D)) >> > (gpu_lengths + SPX_WOTS_LEN, gpu_wots_sig, gpu_sk_seed, gpu_pub_seed, gpu_state_seed, gpu_idx_leaf, gpu_tree);
        wots_sign << <SPX_D, SPX_WOTS_LEN >> > (gpu_wots_sig, gpu_lengths, gpu_sk_seed, gpu_pub_seed, gpu_state_seed, gpu_idx_leaf, gpu_tree);
        cudaMemcpy(sig + sig_index, gpu_fors_sig, SPX_FORS_BYTES, cudaMemcpyDeviceToHost);
        sig_index += SPX_FORS_BYTES;
        cudaMemcpy(sig + sig_index, gpu_wots_sig, SPX_D * (SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N), cudaMemcpyDeviceToHost);
        sig_index = SPX_N;
    }
    cudaEventRecord(stop, 0);
    cudaDeviceSynchronize();
    cudaEventSynchronize(start);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&elapsed_time_ms, start, stop);
    elapsed_time_ms /= 10000;
    printf("SPHINCS+ = %4.2f ms\n", elapsed_time_ms);


    cudaFree(gpu_fors_sig);
    cudaFree(gpu_root);
    cudaFree(gpu_sk_seed);
    cudaFree(gpu_pub_seed);
    cudaFree(gpu_state_seed);
    cudaFree(gpu_wots_addr);
    cudaFree(gpu_indices);
    cudaFree(gpu_lengths);
    cudaFree(gpu_idx_leaf);
    cudaFree(gpu_tree);
    cudaFree(gpu_wots_sig);
    return 0;
}

int main() {
    printf("SPX_BYTES = %d\n", SPX_BYTES);
    printf("FORS_BYTES = %d\n", SPX_FORS_BYTES);
    printf("SPX_WOTS_BYTES = %d\n", SPX_WOTS_BYTES);
    uint64_t siglen = 0;
    uint8_t sig[SPX_BYTES] = { 0, };
    uint8_t m[SPX_SK_BYTES];
    uint8_t sk[SPX_SK_BYTES];
    for (int i = 0; i < SPX_SK_BYTES; i++) {
        m[i] = i;
        sk[i] = i * i - i;
    }

    uint32_t msgNum[10] = { 1, 2, 4, 8, 16, 32, 64, 128, 256, 512 };
    for (int i = 0; i < 1; i++)
        crypto_sign_keypair_test(msgNum[i]);
}