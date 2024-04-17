package fixtures

import spec "github.com/ssvlabs/dkg-spec"

var (
	TestOperator1Proof4Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator4Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator4OperatorsEncShare1),
			SharePubKey:     ShareSK(TestValidator4OperatorsShare1).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("53f81fbdd1240146d6b9d32ebe90145354f7bf528e21455abaca97dfa120984544d0068ce06b8cea4893fe1ea9d99754aaefde2c94dcfb53458331747a5464e2eaa3397b1211cd0946fa3d2fa9157350597bb1a19e7fe3b6709f0c8728ce9a0e0cad269cdc84cbd5b77e8965649ce7286b7da3c6ba4c6e323f242af53a58c0094eb9e715fa9899ebffd2a44c12b86b149f4a08a1ceadbbaa8031980a75ee04f11767983308bf45d8a16120688d4406729380a0e45af6d183e43deb8736167175fb5060840f03057b3ca8114258f4dd42d809a05c41015d4e25be61daa20f28844872a2c8b04743193a4dc7f6bc61e9b8d0efd748651fd76839a2a9576c3644f4"),
	}
	TestOperator2Proof4Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator4Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator4OperatorsEncShare2),
			SharePubKey:     ShareSK(TestValidator4OperatorsShare2).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("a4baf0fa5e1759e6bf6eff78cb69a1490d7f707b1eda653a71ff6c3cc9890dae3c9eda30999bdcfdaf9154acaf262a6690fbc24104933c0c0d30ca03cffb5fa1ba9b191ecef8c3912a1d482b7df99d737a82225ee2b519bceca5cab9cb83db92e5697bb0bfe9d0f24c9dd8d051240dc19f9c9a2aacbf0f97b99fccca0e33aa7005e7231a120bf6a8660d79fd92343ab4581c1184e3fd50ea40823196f5d4d0ab02fd4012f7b903c9abd1ac2c2b478c49de2463eba6a8837d7effea191fb7a42d112e93f051e2abeb60a8d9277ccad00ee72e9aafa7ef893cb5397c46cf2dbeedd82f933057c9df19bd0e2f659b5cca72aac2805f255673bb2c6530522b6a7d64"),
	}
	TestOperator3Proof4Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator4Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator4OperatorsEncShare3),
			SharePubKey:     ShareSK(TestValidator4OperatorsShare3).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("8aad5bc23a85bd8b7e241d3b65cb6d29c27528d5bebb57f8b73decfcb52572153679a05739b5e42711d478d23e4e058556fead4d891a62bf4d8ffb082a92021b4f446ef876300017936aac46b3cf734fc963deedc49e46117d5d7ec6a95c4dc8df00b3af92971c7e9b5c443368887f536aae078493d2bb48dbdd52b13c2c4e85a1276836e0742f01707e40102702f6ded7c604d1e3f20d86a8aa2f983059477376cc22377bd661d60b786c7687d2203eef0af15a6c8fe0079565cb553ef0b89ca4b014d7100f3b56c3f875dec0fa7497ae77b7dbaae68a6b0b4a2bb53064d9d0ec28b1e2086aa11beb1355073a15e7ffb04aca5644ef7dc7c5f8addb0ed1bba4"),
	}
	TestOperator4Proof4Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator4Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator4OperatorsEncShare4),
			SharePubKey:     ShareSK(TestValidator4OperatorsShare4).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("c1615a2ff332059035db2baed39fc3d970b5ae896f62aa7addadd5d4b1f186f7cd3aabe5b1f2d4f95ff0e962b463aa1b8f3af83f49b809e805c2b42c12c79d66ecd540b64391fc48bd43cb1bfa10b47ff33f625b26fe060cfb116b80b1c1543602f26c576d1a23f1d7b7a566ac04dac794e9366bcc0bc91dddc7523604042644f99b35423e7f133dd07231d5c11e6684f0b429a6e9de3188ad05984eef4584bd8a2cb40d96539fcba87420cd013fc0d2cdb5d1e57df6b54ef03bdc8def1e7b33d52b47dc13e8562a890e761eaa6977903d29ab9b2833eae5f64c0df6411cda154f11e8a05aa48ad34a5f7ca2536c8c25daaf2fca7f08795f474d49cff065638e"),
	}
)

var (
	TestOperator1Proof7Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare1),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare1).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("aa05e51db4e8f130037843247ff0495c38c8f30054a5fd19ed47cb83be8cf4f81aa1d0fd6941033f5764294d67354b8bd6a950b70236a008f9412a2265589af46c1dbfcdf2ec38c74e129503f5ec3c587b389ef82c77ff24b28f125e4a134b91b38aa6db87c4a5a52680cdfe2e980e3ff925bfd5fc87ba51bdbe78daa6706bd4404a1fd2cea96756a4a0d7c97c1af4018cecf669f3aea14dac6f72f49787646b147b84cb0694f031ab0095d41f830bc2786d5e1c9e7f021519218e60d37ba048cc9a0f6e35a407df0ef8204aa41c69de8a81ec4b6b23dbdc93c663a5d7028794814a7387d9efcfdaf072e9102a662151c2bde2b5541f1192817d1519d1949566"),
	}
	TestOperator2Proof7Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare2),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare2).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("209f900587526ef934558191cd4a6a949c8985709ceb8bdc2aeccc8319d752ea1ba3eb59a3364b8290e7b3289027417be2b67af6d363e24df00119080a98af7222d4fbb94e219bf72910cfbf9da64914948329ae639c4cd0842c5917618b62de4c9250a8eb84c7b334e52c0cf06e4f7325d59c46f305aeffd2cfd433fcf91756b3069b7c919a21b331011e7192dfc2f7acc30a79ef25ca50ffe91210e0af5c7741cbef99f0e62d3769db89c2a0c51a394d698d1c833dc45a7232d7b20df9fa9d8b1f245e9aed9fb66ee5aadad13c93a0f6b30369fed0bc1ac95b653cb495aa33a4406f8525fcbaecd9c8cf98fd42f775c9754d84c9d2721a114d9885e1b69571"),
	}
	TestOperator3Proof7Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare3),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare3).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("93c8bc04fd0ae686c7d55eb632314e1bc4bfcd4a3f6d6594dc9c4e0b620ecfe75e2f21210d0ea92c2acd77211637feb0dc3cf7b6282903beb5970e6e5f87fba86a737bb91a1e1a99627dee9ab122e2bc8f3e9ed6df94bf4edb4830ce0110c0367371b28bd3243e2d54dd8ddd33d44ddf671c38b6c9c8919e4b772ed5b21bb67e04b9511b9cbf5579214c676090f4a0241a8fe224a535032ea9a84279d1326bc5abb0c0e2efee74e63faac0cc7c986ad7d5617d51716aa19982c090ae2a42dd6bbea903b1007590a8c5f7d6f07388cf260c34642e9b90603537f601e851bd38de0032a9c8c581628afbb0995004c3a79a24671de717ad5239690d0c69fef648dd"),
	}
	TestOperator4Proof7Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare4),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare4).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("adb3f235494c75d5e8c3dc3aa839a1ea46e8720dcb75089528fbfd5910d939e05cd3a8be742aaeb40ccd7872d6d1f69bf89a64f9427bfd45b45455b7a2f285931f571c7cd4950b08eedafdaf28505cf5980b9fe365dd35edd805e9619d37a65e9f0af83f846938a3769fabbd9e6423f2f407d8f56327de47779c93b0ea5cc81dee8988cf8cd283fb24affe7db0c5f10d9696da4b042c2cbdd7f9bef30e80325a4b55edda75a9d64e4498d8639aaf4137a6211b6f8a93406a7232819927ea0f53a1f338eb976c40303d6d08e8597afad430893df7074abe8c9368ca9f855c867f139d0b46f55d4fd930be3ca145dfec5acc3ef010e30d1eaba390284f21e1b287"),
	}
	TestOperator5Proof7Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare5),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare5).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("5409adb7d6972c39c94b291c9a97a071f40f87c7d81b858ddf569e755c8dae7511380773bc6b36e128fe24d268bf153371584f15edb61f16ceb6a53c7b55736dcc7bb27660386342c8648dfff9076e4d7749493af1bd5b5fa0f567dacfb9ca4cbe8ecff4cc50c96e278425d71e795411a8a35142b23801e5142dc2539a5a0fb7fe1537e2e3c63f5ef356c5ba27e35073ad5fd400a4bbbab3e0f83a967d95d580ed391c372dc1e1b34097c2ffe7924c8ae70da5109488894d3041ed3c8f065884233b84008069e6152a89d95bb49a42f4d40f61709654c1d8662dd6e6e7c38ecbc9aa1143f52fcebe001d7bb182fab4a43982b0ecb8dfff0a3c64a41060e772c0"),
	}
	TestOperator6Proof7Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare6),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare6).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("8386a9cf1d4f5fb843398e8b6666dba681399d3a5e127a9b2e383ce74385da5eae2976b51d48af57e7bbc4bb3ddf296c991153971f25f9a6845b222c9be3d2b8c44825cf5d0e9d0b11a48e429e4ccffcbfa319cff36b53f974ad8ebb455c81c50a1c29112caa4977edcdca4d55b7918f3fe05f14072c65cc67851ea427e36bdfe26621bf248f7ee73c5e460ad32a72c851a55bbce466a0ee03d121866cd3c5183906acd632b1503944d725c96d7d413190443affe7357a41a51d53322b1a7be9e849e3b89cd7f3484554289ece145826c5d9785095a3c2f90fe6be02d72a1bde0a20d8ae3c90c20dcf43caf75d2c48c2c6d834714b65545c87d78e434e8ae3df"),
	}
	TestOperator7Proof7Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare7),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare7).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("cedb8791bd457680bb9c0f1dfa5b4526d07199e090736ae82db4b6a0809b0b723a1655b6c84e765e0249746c4fd5a64b6698d3fb73819c9aa784208d35effae6e38e7a012e937bdf456e862b427e94fe9f233f6c37699c2e1b88c92873ec2b808254dd9501a7b7df3c5d0a0757cc3f0f6b96c9d78c00fdd3bf0314688ededea0f78dc512dcaf7a4c8c37236740dc635950ff14fb80186e03d06d32622051b44102d0665d684f8b67f0a21b6a6dbf51edbe9a6648c57e2af396b7dc97c2badc23b0c50ce30d38618b9a1cc31c7ae254c951de2154e5373a9030da9f8d70d3906bdc6e0144917bbf26f1af761df848787e795a89d34d2586d7710e594f1ef2b996"),
	}
)

var (
	TestOperator1Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare1),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare1).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("2dc181d957eba48a79c3e71a5cad5be1517f2154bde3f377601a0a13038fe29cab6c1c4f8235a8ea6f09ac3fd417a54440f2a45f3afebc28c7306fdefd882bcf96f004cfdab7b71dcc8a4db3485e0e38f1fc2e0292b212525a94bc33da0cf8f52abcd73bc1fc989e1d65ae24eb9eb47280dce9d879d91d850ccab20e068d4b2e40b0e8f6cb27676bd64974ed2d3b2b2a54012997b4485d27277b7fdcce1cf14ae71dde4b26ac033976deecf433f56f7e24c46cb3cd57696930f43e1c51cf393793c26de3391611613a426f6f700c73230672b562e608306c639a0f5c655777b5f7f10d0d82733593b0ad7f298f0143c8357af529fa5bc031ab0dba26de82d7ac"),
	}
	TestOperator2Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare2),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare2).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("491da79c178f20b911264279d662f62562a2bc932986228ce5b8e7a00bfd5db6a81b0c7cca706cd6ed3a83f1000bcba05c0302a7d7dbff6f9fd65e956921432a6eef49baf86b6798f5e999ed554707ad9364d7483024b0ea006b859729057f293de91f1da50db9b6fb44b9b757c856e33988acaa0fc8ed79ff7391c6b3fa58a768ffa498e3879c338ecdd12789accc666cc29b3fdc0f88d9348b10832f20f518123432deb6b74179a7ee12d1f46fed14123b9e95b152d92d566262a5a46539af1ac14d6d57b64481fb0754fef3fc31c82d0931c0e5718a3547d628774a55d6ad0b4a149b1dfbfe63c28e14bf1e2cf450929d5c03636b8abab5f469f0ec920a97"),
	}
	TestOperator3Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare3),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare3).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("3ffd039cb91b943b6fbbf0962bbb3cbfcd839241de586ea2b320c08d7b0d10e7db4bf7239919df260ea4d84c2a1199a072b4fc1be7f5f7b5947f72440e04f605bd9f00518643c786581b3d6d900b3b160a325cd6681d29fe207f5d6672f22e45f35805eb5a0058685bc5f84cbdc3cb5bcdf2cda37e9247c6177abfb9b34b4fcc59c7d4d94b19ac4762ef84298b9697d1eab18138cb9299c9d2d832c9d1f8926a9a4068e68d9a900ab3cee41beafc51e023e5c43e2f9710c43880dfade388534e09fd1483dbfb9118431485aa7c1bff7fb5845a3f653155fa356679a359285e6a6d1215cb2567866bde9b48f6d85f39de26273997f098a41f13aa67706bb28971"),
	}
	TestOperator4Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare4),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare4).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("9e68ec19c6b895598be287c7fe9a843faac8ee91710d6756e3aa0bd160d33ca9b3dd8bf5508217ac3d553ad5d39168e1362b8db263b56a6be8f797b7aa3ee63b1eebe1df17f8acaf0ee97edab90d1c307cccde1e89116d1e2ceb660ba23cce4237233f384a62242726a3eceb0307937561bb1ec605fce02c2005932ceff4776a304d24518e582cbcba3f8a6af5ef33a5efea0548861664f40e7d4d963c8ee364b00cfb683ae2e877872fbbb15199eb11ccb11a59c6597e1262eb9c94ac9c621765b8fbcf49a40107eb55dd37fd403236b5733d3647c9d1d3fe308883323ea90efbf528be6695fd1d90fda34edbbb252b4f827243474824e825dfcd52994b192f"),
	}
	TestOperator5Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare5),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare5).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("1cf74d8af86aee4f3de8797dc99fb3aff3e73ff6be7560a83f66ae953e537207b7d1d36e41cf2fd492dc840b2c63f0ce2dc92322520ade21753b16bb2a9698e91136425f1af0ce218079bc9b747a92c0e7931b54394d2875b8f226bb80cc1e798e6b850228bc85059f954847c357ce53a27d52df20548ef96bae63b07e013989a03335287e39ca1e58398fd368cfc72f35d7efe256153584bf10a3a39939027b538303b24808e3360ea82f8b16159110277deee6c7801390f29647b8c58553bb89cece61d5c46e5b584f660b003eb44388270df653b1503d20ecaee734638e697b03bd3a071ba799eac9d29fbf9cc7f6e8b4dfeadcbcb463aa28d3e2bb362cde"),
	}
	TestOperator6Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare6),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare6).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("2a1760d2a9f247a598ba5fb8194dbb4e1d7961a786ef254c17fe11f4a2c3b96af8548ee99ed214cf7bd4074c6e9afbaab3814b4c15127f52f31460bb403283a025429e6f730c6033ae5b04e240b5a97104e5144ac329901c80f90777d892f5623a63c0badd3590c418f0b4a444d4aa9547195453ec37873ec4256c07aef0f825b7ec2b9918b9c36889c28eb01ee82437c7cdf28083c696fc228e5b00433a5cb7f94307684585ef9e03dd4c4a23874a1f98449d7804d0ec378f610ea717e744033c1fddaaaa60f7b103445efd2fc4312d96633c8c6ca9ab27c59293be2aa09d47fdc50e473fdb74513997a79b9117ecc71e19756414e544a75b74d1da81006b0d"),
	}
	TestOperator7Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare7),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare7).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("2c323e687486adc56f94207e5b8c72493712ad60dfa1a55d50b9142d8722b779257b3344ca55729013b9d4db6983518b91a40625fe18b6c434f71c6a97bef3df3e5b902c144f697f39f7521578b8f25875fe67f66e5f6e937e26fcddbf8fb908fda12cdfb899b65d4487e8f6215f40d01438dda375c9dfb191e5ea61fe5a59c0f3f884bfddbb87b6b451aa07be2eda2cdd7c8b92a851a89e43a84885893b02ecfae2b7129917dd63f1db0cea3749353dad87c74fe22f8a69b24b421b1b168103baac67bf2be96d7bd086632bd466edd21987c18309619c3df15985d298c49db18a4544aec2ce326261338164123578ab3ac26150d3cea8d298cc41dbc1851d92"),
	}
	TestOperator8Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare8),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare8).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("249b9ac09ede6d456c4dbb5e509c4d289f56a92e7feb23ec86108d05b3f4563ae6a1fea79907829366013ecaff1bdab8f3d2ace7e1d21da41983ffea4da8df1c68d2ec5f3ab5075cbf344393726bc27125132ad43874d714fc0d78eb3fefe85127660bebf32e400c7705240eae7b7ffdd8728b8e30411e042e970f010be85f087e89d5b3830c413606e080f90500432c1b02bcc64b32fb8e37224623ced9cc62a952b8bb985213e505abef8b5d716372a647adf6ba2ce90bcb537241ddf93006986f771bd915a456e6d338f2b42b1f03d19b3dc16ce3b0c0c07834db167b1bade342a93627c372a071df3319e0aa3e9578f55d37329362aacfea0097c69e90ec"),
	}
	TestOperator9Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare9),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare9).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("6c5a8e69ac201928d5a9c71cd651012448a279ee65ed8c2b6ae9ab5baefdd93cb28e04188f3e2b160c57694ab60f13e0efc6c08c4b117ff72222767f03660854e79b8976226615862ffc87da4d58ab573decd556dc727a9f8edb153847e612c5bb856a007e1f549df5192aeefa018467acd70ec578683e1e39f954fb7d10b1adcbe500aff13ec0203c41ed42d7aae168eee9c6eac620c3303dcb5ab08f79f2130a5737ca3ef6355afe8b69d80fe3ada7e7908f4540a33bfe86a013d9cfbcb55fe9c7df361f0e2c161996889f3ae26275b1794afbe447eb0750aacaf06cb09c09344b74b4ac0140a930712c549d680224a43250bbc241a4227541aad7a036c136"),
	}
	TestOperator10Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare10),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare10).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("ca3b6e47f23313700903d6f203ebd5a322ebb7e180f67c61257217ca1bd92a495ead376d2c742fde9cd1d4a18fd351093c693a1c93ecb7c9f5d215e1541b418fcfcc65e9bc5026b8aa2c554dd10841f7a8c89cf9577c2131fb0377e896e822c1cec88d6e878d5828f77daca458085ca794b27082df0cd434fa3183cab2ee6eddd5ad7e95629e9bf4b2df243f196162ce3473d7915af081ce7f2f70054072c0c9b6288f08786f2d5e1610233d248a6933bd15540f9017be93dff3d8d29b174c04373895c830969a14fc122f87ef503b934f8fdb0643f4e6994ba5261abb205d803ddc359098976a90c5e4f8958a03203a907fd8688d32db0d992ffec955354c28"),
	}
)

var (
	TestOperator1Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare1),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare1).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("0dba1c2249c8fdc1db3646a48c6d71dbc00d7187bb62f968ef55d4c985a095ee3d69eb26b0259cddb4b0659f97ce63961ebba9654cc5d85c2a31a0c05cecd22ddc6ba6b77cfd8b75cf1db41571513099ed96b5449521218ea4acb1b2e7739246fb8a389b62003e76a23b861b8b7dba9da16db71f7e17f5393457db4d99d9e51fafd09043e0638cfd6a790158228a70eb7b708aa48c8d02d6b615c4dbf50111f5b0f80fc61ac2154cba2d798908800ec4468962faadaf9503b1d6719a14a59361a1616a768a096a9eee9a42180b7e177d629ef19c1ff11581804fb760cee7a856ff2984d89679758981b5333e5ba4e00f244b5e3b3b632bfc0024df6aac569519"),
	}
	TestOperator2Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare2),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare2).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("b8a762378b99a29b7ab59b26c4b50912679e6f12e5c50ab7b12a43aa45a99093bdedb374840044d1e7f92f0153687665af8a0477f983e1b678a1efa72a1f6ea08c695a5b9a37cb61252b3cdf2a51622620093915926c01fa3591b9a92c7ced25a32801337cabb3bc7ebeff3a42790f42b758369d772d42757b9cf49bf967fbea282976bca137b187b3ab845801eaf090d68fad5e3d7c50a6d3b57a15767781dfda73842dffd5508ebf901d44284d6969cfc4d5079f8e44526134b48addc1af34c0764ae7735efad9fb6f7cc324a71690b0ebbbf036af95bde9618d6d69a84f7f1b4af7c2daea37335207474be6e4a8f01d3471d01ce2adaeff895c296da9deea"),
	}
	TestOperator3Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare3),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare3).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("674e83d553923715640befca4ac1435d792d4570a29844e8f2123133894e830cd7db1394eaa2a281d756482b4182135852a3b79d1d07d6d43d455e06e76ea7a4ec4fc0dc5c4d3d250116a1502aafa63bb48eb59910df1b230f49e0a3e1ac1b24bedad98bfaa6358545041ccadc3640241501e4c3b095869f9c5fb541072d46698c947545149290d5114205f45265c762cf455dfeec16e300ea4a38b3fbd28f1a2367e99443cac443a8a21cff7ecdede2e83b9523025b6e66385d75c1fe36d4d0173c4168b05e11c9a9e083ff79a0a38978faf99918ce6e5fe7ade7714daa37eefc7d325141471561622969d956d01a0818421d3450f6f65b63c8ae3920c16c26"),
	}
	TestOperator4Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare4),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare4).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("8dcb4b5929df49adc81ea37fae26fc1c6cbe9eaf33160ccb971f06e3c623e06a007cfe7fe345fc0e01f7ccc14b0015eafb0e3230b5942858b644208db04100259807138e3624e356c74256ac888f5f8c9d885fe703b009e3e09a488562331d83549e063fbdd430c27304d837e29803f493fcfb62f8f9ec587f5618e6e48a9f9ec7bd94685efd4288e255c6215c81962c7078080801f560f1254bf8746f5440c4d861ff9107423adb79ea2e3cc3771472ca4908d3bc72d66b3b46f192f909ee2e5fcd85420ed0fd1d1322eae333b521d1ef787c0aaa801b96fefb52a8912b4003860d3607c1ebf9caca7b1ab41eb51145cb28969da363c31b7443aa44df18e379"),
	}
	TestOperator5Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare5),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare5).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("85d0f0310b4f53665e365e8d8937539d1dc2a52fa77c72ae76e2c5dc39b967a4ac9a7a8ed0b10dcee0eb3816df10c19b868e4b0b3dcc56d1e412ba5f3853d8defe6eac6136371fa008e0c38f783d11e23050f3125268574fdf1b84b1ef8f721b16a061a2cb319e9f8a95ba3fa0efb893a373f1c1627f6aa839a7d05f98316a944f069e2bed3b9a60e859219eec49af5230477641cb0bdf171f34e1b20cf632171a3ba5d99714e78d3dcb6a8bdfb7005ddb1cfe9aa64f26061e5354bbd38d9e2e516ca9ec2db485d84f2d61db7b93ba53b4f9cb7e543a93fd08bcb3a3f4a7fc03501a96a4688fcf1da13e5fc3cda0026192b1c0b7c7f51c161e998d8a20795fa9"),
	}
	TestOperator6Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare6),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare6).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("6f52705e370ed93935691622241e33db75ae0d4e02f252b48f53263753143e6ab2fa7034816a29154c16cd7f0dde5d44c21fc06062f7b82a2eab9777b5c0bfa8336d858a06cd1b42e61d32cd0011d4d22421a84e20d07a45d581910f8a76aedcd256165ca639186ca509f4cd5d10b0ecb3c92849d78d9cca0d5706f14df9e42046ab85ddb556b281e3a3a095f492c953584a56dc18785688adc8279a0c55407d97d79d6b5af8dc653d76128b1b4ad92994d64679678bfd7569e37e1281d1d0d0bf4303bd8abf2018afa8497ce2f51c53d16e4f88e46886a9e87958ab238b40d9a0690505cbcb18c5a2e53a4e4c6ab2f23702edefb6137249d26acbdfeb57c163"),
	}
	TestOperator7Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare7),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare7).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("1818d80b4ef347754090caa2b0a69af4170ece5837003baaa4ff855638c74acd07bd07a100dcbfbe746c9af76659b64ccfc2778794ba71cc643f29143d9757cc4d605f9d414086dde9764bac018f58af26c7090247cfd75a238e6899c4643f103d033c0c79f2bd40c4c62072240e561003a157eac88a0fe4610c4c441753e8cc5f8143f27bf4aa202251124fcd81bf5241849058c681b0995bd27b2754c9b62398b365d97f1b2a9870fec0d102c3e4706ecec893845dc561d6efb6629ed82dc10e37620b269802b012e53e375d5a51e5b445f8fb7e5fe2ee729239af670e8903c8bcbe3541302a25e88ba9c0d8443c5b547ac6b30d14d569b5c844812edd7594"),
	}
	TestOperator8Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare8),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare8).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("1d727786825737657574b22fa3d4da80ca4b24fae0e759ca6f07cf07391165b49239bc5b9c73edfb1d292ad572db96037ea8eb23f8650dbec2ee9d8fdea4434ed0d6afb1bfe1bb557134388986df499565ffc547937f99cbda02e1bc58e32caf0cd9baca13798188f81e4861ea47e924d140b467f9be995f5d295eba4c1e257061667afa8ed8e11c9639c373a99b035c289593e724ad4defa572dc27c84ee55c8e5a432012df82cb5f1e74d9fdaddfeb2df0bf680d62d1e015f9e9672fa7814aee4c3ce27ff37c90949e2b8a7cb844e2eaae95620a342a613b8ceb10786e4f1f478e1f1dbc8d813390ed9f62d13c4670227e117049d5ae290caa380fbe49bb29"),
	}
	TestOperator9Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare9),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare9).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("8884912b5fde4ec9249b3939c5fa704ee88895f9f3ec96bdb902a22e605d5f646e76c18b5dccabebb6d8a2b0e17087c2edf65ec8011e6d148a47b752296dca784ca3b4004d0787c5b4bf1ce5f08dbbdb06bee295cdcdef7df4db23a03a799a5b8982fbba5a066d3e862865b68609e1eda2f33ef9e575eed624241fb6d64c96311b1fb3407351a3cd594f75c82f59be9a372ea64b056bce2a792b2ac27d97ff66ce87dd59619e9e1eb676da566d3907b90a045162c6a7f307257385b33e8efe757200123522bd94a36fd4b443fa967532242efb292532a26d6a0c421aa1438530095b8445a2c81de21efc450c57d8301bbad617c609ccf5bd89d02a63dab6f4eb"),
	}
	TestOperator10Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare10),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare10).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("4a5da341368d17cee60b47b6e3415473f6f1af2d67442442f783d387914574f1d223ec4266ec3c9e4d969cc1e902044107b45fdebc8f3dfe616ae1028649826f7e11111b1537f537be03f2d464aaf7e45b8514bb0142ed2a3e5809fb7d85e120210fbfa510a663dc53d16224f36376a421963ce670952eb82f65a1d40407e0331b63d24d939d5bb7fc075dad1e44232b8af89272e52fcb49d48fa8c5f4237ebe4f8ef0e37e6d5db2ad05451e8f652efabb28d5ce2143d52b09ba46714fe8cdc67bdcc5beb1eeab8b21efbdcc3172ab17c2cc942c1fb4eec6a4cb2d3e327e6ee5cb2b09c3b440ec153b2e33dbc834956a2dda49fcbbacb4d10ea5c7bede5b07ef"),
	}
	TestOperator11Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare11),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare11).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("6a1d213e65c9c3362a285024ed0cc6f84cc4f57497d4ec1c1163681cef5fed7cafbe1e51c6bc818399d7c19a9e5904ed8f9e5654e8211cbe7d4ae39ef768aacf9504a83a630c9d3f468f5ed07052d4b7415b460819187431b03c1bbd37822c3c86699a3f292384733595d94386baa9870849d07a3d3adf0063b8fd60093d43e0e49a8ed57d25b8bc05f5b36678d14abfe06727d35e3840e3ed59dbb8330ce15570b284be4dcc7c6a5f2a5debc4958a1a4efb720f3169f84e8fb2069e2767e0abc6fe5168b919c56b383f91e897c350ffe023b7cf08f1000132dff3cf0b1dc5edf6700efb588d95a39742eb634235d9684648e46f8a13a472a28622bbd57745ca"),
	}
	TestOperator12Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare12),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare12).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("6e415dc6530a82e465277f4c9718de580e653ab777c3a43398cfeb818dab931619b8983291787d68200674564b7c785f8325923fc4933b5108d2af4bd6c87d25b6906d86edfa5502f263124c15eb99f7eabf82a71cba3ed7179eec2d0384b725c7c763ed63a88524ad28f3604a4e716922bbcb685d2ec168b554b4e0f84df1c896b7f75fd0a059984f54941bb79016012e5ef5c840ce76981d277dd44989cdc93b265b2fe3098c92248eee25b256c91e39da98952ff33618ee67aee10a1fed6bab27904b3e98753b8aaed74ae4ac0db6a174d22aa5bd41ded162c9583eac112b506945a8a92e23e697318fa89c1668960902ad9fc0686685ce6b79c61a5ce833"),
	}
	TestOperator13Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare13),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare13).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("46ad6e2a3c7097a93233047053588d896654ca22e06fbc38231b1908e4b811ed5d2d7fd99ea8a7f403c93ffcf880dbffa6207286aa485cd10055da678bb89c1c1c3f45c7966af16ce9e8fed848672de661b82c163964cb80224fe004ebea0c2df964b2e02e3c92ece23c8d5fa8dcfc84b79ec4f3d7d543f536f623e76f3bd300d65a5b43d4d6d5fb414cdae1c6e6c82a0767c51afdc96397dd12f436f0cd022a7dfe0a5e04a9d365179011105ed3f016fa6586cfca816a0879e39421022303b3fb18e678265ba8084e0580479f1e51e485b5830288ad6b4a32c6e3bc5d29d10ea45724c24f1a9f3277d84408339f9507abb521eb5180380f3945db76fd04da24"),
	}
)
