using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace YG
{

	#region Exceptions

	/// <inheritdoc />
	/// <summary>Exception for signalling parse errors</summary>
	internal class SaltParseException : Exception
	{

		/// <inheritdoc />
		/// <summary>Default constructor</summary>
		public SaltParseException()
		{
		}

		/// <inheritdoc />
		/// <summary>Initializes a new instance of <see cref="T:BCrypt.Net.SaltParseException" /></summary>
		/// <param name="message">The message</param>
		public SaltParseException(string message) : base(message)
		{
		}

		/// <inheritdoc />
		/// <summary>Initializes a new instance of <see cref="T:BCrypt.Net.SaltParseException" /></summary>
		/// <param name="message">The message</param>
		/// <param name="innerException">The inner exception</param>
		public SaltParseException(string message, Exception innerException) : base(message, innerException)
		{
		}

	}

	#endregion

	#region BCrypt Class

	/// <summary>BCrypt implementation</summary>
	/// <remarks>
	///  <para>BCrypt implements OpenBSD-style Blowfish password hashing using the scheme described in <a href="http://www.usenix.org/event/usenix99/provos/provos_html/index.html">"A Future-Adaptable Password Scheme"</a> by Niels Provos and David Mazieres.</para>
	///  <para>This password hashing system tries to thwart off-line password cracking using a computationally-intensive hashing algorithm, based on Bruce Schneier's Blowfish cipher. The work factor of the algorithm is parameterised, so it can be increased as computers get faster.</para>
	///  <para>Usage is really simple. To hash a password for the first time, call the <see cref="HashPassword(string)"/> method with a random salt, like this:</para>
	///  <code>string pw_hash = BCrypt.HashPassword(plain_password);</code>
	///  <para>To check whether a plaintext password matches one that has been hashed previously, use the <see cref="Verify"/> method:</para>
	///  <code>
	///    if (BCrypt.Verify(candidate_password, stored_hash))
	///        Console.WriteLine("It matches");
	///    else
	///        Console.WriteLine("It does not match");
	///  </code>
	///  <para>The <see cref="GenerateSalt()"/> method takes an optional parameter (workFactor) that determines the computational complexity of the hashing:</para>
	///  <code>
	///    string strong_salt = BCrypt.GenerateSalt(10);
	///    string stronger_salt = BCrypt.GenerateSalt(12);
	///  </code>
	///  <para>The amount of work increases exponentially (2^workFactor), so each increment is twice as much work. The default workFactor is 10, and the valid range is 4 to 31.</para>
	/// </remarks>
	public sealed class BCrypt
	{

		#region Enums

		/// <summary>Ревизия соли</summary>
		public enum SaltRevision
		{

			/// <summary>Ревизия 2</summary>
			Revision2,

			/// <summary>Ревизия 2A</summary>
			Revision2A,

			/// <summary>Ревизия 2B</summary>
			Revision2B,

			/// <summary>Ревизия 2X</summary>
			Revision2X,

			/// <summary>Ревизия 2Y</summary>
			Revision2Y

		}

		#endregion

		#region BCrypt parameters

		private const int GensaltDefaultLog2Rounds = 10;

		private const int BcryptSaltLen = 16;

		#endregion

		#region Blowfish parameters

		private const int BlowfishNumRounds = 16;

		#endregion

		#region Initial contents of key schedule

		private static readonly uint[] POrig = {
			  608_135_816,
			2_242_054_355,
			  320_440_878,
			   57_701_188,
			2_752_067_618,
			  698_298_832,
			  137_296_536,
			3_964_562_569,
			1_160_258_022,
			  953_160_567,
			3_193_202_383,
			  887_688_300,
			3_232_508_343,
			3_380_367_581,
			1_065_670_069,
			3_041_331_479,
			2_450_970_073,
			2_306_472_731
		};

		private static readonly uint[] SOrig = {
			3_509_652_390,
			2_564_797_868,
			  805_139_163,
			3_491_422_135,
			3_101_798_381,
			1_780_907_670,
			3_128_725_573,
			4_046_225_305,
			  614_570_311,
			3_012_652_279,
			  134_345_442,
			2_240_740_374,
			1_667_834_072,
			1_901_547_113,
			2_757_295_779,
			4_103_290_238,
			  227_898_511,
			1_921_955_416,
			1_904_987_480,
			2_182_433_518,
			2_069_144_605,
			3_260_701_109,
			2_620_446_009,
			  720_527_379,
			3_318_853_667,
			  677_414_384,
			3_393_288_472,
			3_101_374_703,
			2_390_351_024,
			1_614_419_982,
			1_822_297_739,
			2_954_791_486,
			3_608_508_353,
			3_174_124_327,
			2_024_746_970,
			1_432_378_464,
			3_864_339_955,
			2_857_741_204,
			1_464_375_394,
			1_676_153_920,
			1_439_316_330,
			  715_854_006,
			3_033_291_828,
			  289_532_110,
			2_706_671_279,
			2_087_905_683,
			3_018_724_369,
			1_668_267_050,
			  732_546_397,
			1_947_742_710,
			3_462_151_702,
			2_609_353_502,
			2_950_085_171,
			1_814_351_708,
			2_050_118_529,
			  680_887_927,
			  999_245_976,
			1_800_124_847,
			3_300_911_131,
			1_713_906_067,
			1_641_548_236,
			4_213_287_313,
			1_216_130_144,
			1_575_780_402,
			4_018_429_277,
			3_917_837_745,
			3_693_486_850,
			3_949_271_944,
			  596_196_993,
			3_549_867_205,
			  258_830_323,
			2_213_823_033,
			  772_490_370,
			2_760_122_372,
			1_774_776_394,
			2_652_871_518,
			  566_650_946,
			4_142_492_826,
			1_728_879_713,
			2_882_767_088,
			1_783_734_482,
			3_629_395_816,
			2_517_608_232,
			2_874_225_571,
			1_861_159_788,
			  326_777_828,
			3_124_490_320,
			2_130_389_656,
			2_716_951_837,
			  967_770_486,
			1_724_537_150,
			2_185_432_712,
			2_364_442_137,
			1_164_943_284,
			2_105_845_187,
			  998_989_502,
			3_765_401_048,
			2_244_026_483,
			1_075_463_327,
			1_455_516_326,
			1_322_494_562,
			  910_128_902,
			  469_688_178,
			1_117_454_909,
			  936_433_444,
			3_490_320_968,
			3_675_253_459,
			1_240_580_251,
			  122_909_385,
			2_157_517_691,
			  634_681_816,
			4_142_456_567,
			3_825_094_682,
			3_061_402_683,
			2_540_495_037,
			   79_693_498,
			3_249_098_678,
			1_084_186_820,
			1_583_128_258,
			  426_386_531,
			1_761_308_591,
			1_047_286_709,
			  322_548_459,
			  995_290_223,
			1_845_252_383,
			2_603_652_396,
			3_431_023_940,
			2_942_221_577,
			3_202_600_964,
			3_727_903_485,
			1_712_269_319,
			  422_464_435,
			3_234_572_375,
			1_170_764_815,
			3_523_960_633,
			3_117_677_531,
			1_434_042_557,
			  442_511_882,
			3_600_875_718,
			1_076_654_713,
			1_738_483_198,
			4_213_154_764,
			2_393_238_008,
			3_677_496_056,
			1_014_306_527,
			4_251_020_053,
			  793_779_912,
			2_902_807_211,
			  842_905_082,
			4_246_964_064,
			1_395_751_752,
			1_040_244_610,
			2_656_851_899,
			3_396_308_128,
			  445_077_038,
			3_742_853_595,
			3_577_915_638,
			  679_411_651,
			2_892_444_358,
			2_354_009_459,
			1_767_581_616,
			3_150_600_392,
			3_791_627_101,
			3_102_740_896,
			  284_835_224,
			4_246_832_056,
			1_258_075_500,
			  768_725_851,
			2_589_189_241,
			3_069_724_005,
			3_532_540_348,
			1_274_779_536,
			3_789_419_226,
			2_764_799_539,
			1_660_621_633,
			3_471_099_624,
			4_011_903_706,
			  913_787_905,
			3_497_959_166,
			  737_222_580,
			2_514_213_453,
			2_928_710_040,
			3_937_242_737,
			1_804_850_592,
			3_499_020_752,
			2_949_064_160,
			2_386_320_175,
			2_390_070_455,
			2_415_321_851,
			4_061_277_028,
			2_290_661_394,
			2_416_832_540,
			1_336_762_016,
			1_754_252_060,
			3_520_065_937,
			3_014_181_293,
			  791_618_072,
			3_188_594_551,
			3_933_548_030,
			2_332_172_193,
			3_852_520_463,
			3_043_980_520,
			  413_987_798,
			3_465_142_937,
			3_030_929_376,
			4_245_938_359,
			2_093_235_073,
			3_534_596_313,
			  375_366_246,
			2_157_278_981,
			2_479_649_556,
			  555_357_303,
			3_870_105_701,
			2_008_414_854,
			3_344_188_149,
			4_221_384_143,
			3_956_125_452,
			2_067_696_032,
			3_594_591_187,
			2_921_233_993,
				2_428_461,
			  544_322_398,
			  577_241_275,
			1_471_733_935,
			  610_547_355,
			4_027_169_054,
			1_432_588_573,
			1_507_829_418,
			2_025_931_657,
			3_646_575_487,
			  545_086_370,
			   48_609_733,
			2_200_306_550,
			1_653_985_193,
			  298_326_376,
			1_316_178_497,
			3_007_786_442,
			2_064_951_626,
			  458_293_330,
			2_589_141_269,
			3_591_329_599,
			3_164_325_604,
			  727_753_846,
			2_179_363_840,
			  146_436_021,
			1_461_446_943,
			4_069_977_195,
			  705_550_613,
			3_059_967_265,
			3_887_724_982,
			4_281_599_278,
			3_313_849_956,
			1_404_054_877,
			2_845_806_497,
			  146_425_753,
			1_854_211_946,
			1_266_315_497,
			3_048_417_604,
			3_681_880_366,
			3_289_982_499,
			2_909_710_000,
			1_235_738_493,
			2_632_868_024,
			2_414_719_590,
			3_970_600_049,
			1_771_706_367,
			1_449_415_276,
			3_266_420_449,
			  422_970_021,
			1_963_543_593,
			2_690_192_192,
			3_826_793_022,
			1_062_508_698,
			1_531_092_325,
			1_804_592_342,
			2_583_117_782,
			2_714_934_279,
			4_024_971_509,
			1_294_809_318,
			4_028_980_673,
			1_289_560_198,
			2_221_992_742,
			1_669_523_910,
			   35_572_830,
			  157_838_143,
			1_052_438_473,
			1_016_535_060,
			1_802_137_761,
			1_753_167_236,
			1_386_275_462,
			3_080_475_397,
			2_857_371_447,
			1_040_679_964,
			2_145_300_060,
			2_390_574_316,
			1_461_121_720,
			2_956_646_967,
			4_031_777_805,
			4_028_374_788,
			   33_600_511,
			2_920_084_762,
			1_018_524_850,
			  629_373_528,
			3_691_585_981,
			3_515_945_977,
			2_091_462_646,
			2_486_323_059,
			  586_499_841,
			  988_145_025,
			  935_516_892,
			3_367_335_476,
			2_599_673_255,
			2_839_830_854,
			  265_290_510,
			3_972_581_182,
			2_759_138_881,
			3_795_373_465,
			1_005_194_799,
			  847_297_441,
			  406_762_289,
			1_314_163_512,
			1_332_590_856,
			1_866_599_683,
			4_127_851_711,
			  750_260_880,
			  613_907_577,
			1_450_815_602,
			3_165_620_655,
			3_734_664_991,
			3_650_291_728,
			3_012_275_730,
			3_704_569_646,
			1_427_272_223,
			  778_793_252,
			1_343_938_022,
			2_676_280_711,
			2_052_605_720,
			1_946_737_175,
			3_164_576_444,
			3_914_038_668,
			3_967_478_842,
			3_682_934_266,
			1_661_551_462,
			3_294_938_066,
			4_011_595_847,
			  840_292_616,
			3_712_170_807,
			  616_741_398,
			  312_560_963,
			  711_312_465,
			1_351_876_610,
			  322_626_781,
			1_910_503_582,
			  271_666_773,
			2_175_563_734,
			1_594_956_187,
			   70_604_529,
			3_617_834_859,
			1_007_753_275,
			1_495_573_769,
			4_069_517_037,
			2_549_218_298,
			2_663_038_764,
			  504_708_206,
			2_263_041_392,
			3_941_167_025,
			2_249_088_522,
			1_514_023_603,
			1_998_579_484,
			1_312_622_330,
			  694_541_497,
			2_582_060_303,
			2_151_582_166,
			1_382_467_621,
			  776_784_248,
			2_618_340_202,
			3_323_268_794,
			2_497_899_128,
			2_784_771_155,
			  503_983_604,
			4_076_293_799,
			  907_881_277,
			  423_175_695,
			  432_175_456,
			1_378_068_232,
			4_145_222_326,
			3_954_048_622,
			3_938_656_102,
			3_820_766_613,
			2_793_130_115,
			2_977_904_593,
			   26_017_576,
			3_274_890_735,
			3_194_772_133,
			1_700_274_565,
			1_756_076_034,
			4_006_520_079,
			3_677_328_699,
			  720_338_349,
			1_533_947_780,
			  354_530_856,
			  688_349_552,
			3_973_924_725,
			1_637_815_568,
			  332_179_504,
			3_949_051_286,
			   53_804_574,
			2_852_348_879,
			3_044_236_432,
			1_282_449_977,
			3_583_942_155,
			3_416_972_820,
			4_006_381_244,
			1_617_046_695,
			2_628_476_075,
			3_002_303_598,
			1_686_838_959,
			  431_878_346,
			2_686_675_385,
			1_700_445_008,
			1_080_580_658,
			1_009_431_731,
			  832_498_133,
			3_223_435_511,
			2_605_976_345,
			2_271_191_193,
			2_516_031_870,
			1_648_197_032,
			4_164_389_018,
			2_548_247_927,
			  300_782_431,
			  375_919_233,
			  238_389_289,
			3_353_747_414,
			2_531_188_641,
			2_019_080_857,
			1_475_708_069,
			  455_242_339,
			2_609_103_871,
			  448_939_670,
			3_451_063_019,
			1_395_535_956,
			2_413_381_860,
			1_841_049_896,
			1_491_858_159,
			  885_456_874,
			4_264_095_073,
			4_001_119_347,
			1_565_136_089,
			3_898_914_787,
			1_108_368_660,
			  540_939_232,
			1_173_283_510,
			2_745_871_338,
			3_681_308_437,
			4_207_628_240,
			3_343_053_890,
			4_016_749_493,
			1_699_691_293,
			1_103_962_373,
			3_625_875_870,
			2_256_883_143,
			3_830_138_730,
			1_031_889_488,
			3_479_347_698,
			1_535_977_030,
			4_236_805_024,
			3_251_091_107,
			2_132_092_099,
			1_774_941_330,
			1_199_868_427,
			1_452_454_533,
			  157_007_616,
			2_904_115_357,
			  342_012_276,
			  595_725_824,
			1_480_756_522,
			  206_960_106,
			  497_939_518,
			  591_360_097,
			  863_170_706,
			2_375_253_569,
			3_596_610_801,
			1_814_182_875,
			2_094_937_945,
			3_421_402_208,
			1_082_520_231,
			3_463_918_190,
			2_785_509_508,
			  435_703_966,
			3_908_032_597,
			1_641_649_973,
			2_842_273_706,
			3_305_899_714,
			1_510_255_612,
			2_148_256_476,
			2_655_287_854,
			3_276_092_548,
			4_258_621_189,
			  236_887_753,
			3_681_803_219,
			  274_041_037,
			1_734_335_097,
			3_815_195_456,
			3_317_970_021,
			1_899_903_192,
			1_026_095_262,
			4_050_517_792,
			  356_393_447,
			2_410_691_914,
			3_873_677_099,
			3_682_840_055,
			3_913_112_168,
			2_491_498_743,
			4_132_185_628,
			2_489_919_796,
			1_091_903_735,
			1_979_897_079,
			3_170_134_830,
			3_567_386_728,
			3_557_303_409,
			  857_797_738,
			1_136_121_015,
			1_342_202_287,
			  507_115_054,
			2_535_736_646,
			  337_727_348,
			3_213_592_640,
			1_301_675_037,
			2_528_481_711,
			1_895_095_763,
			1_721_773_893,
			3_216_771_564,
			   62_756_741,
			2_142_006_736,
			  835_421_444,
			2_531_993_523,
			1_442_658_625,
			3_659_876_326,
			2_882_144_922,
			  676_362_277,
			1_392_781_812,
			  170_690_266,
			3_921_047_035,
			1_759_253_602,
			3_611_846_912,
			1_745_797_284,
			  664_899_054,
			1_329_594_018,
			3_901_205_900,
			3_045_908_486,
			2_062_866_102,
			2_865_634_940,
			3_543_621_612,
			3_464_012_697,
			1_080_764_994,
			  553_557_557,
			3_656_615_353,
			3_996_768_171,
			  991_055_499,
			  499_776_247,
			1_265_440_854,
			  648_242_737,
			3_940_784_050,
			  980_351_604,
			3_713_745_714,
			1_749_149_687,
			3_396_870_395,
			4_211_799_374,
			3_640_570_775,
			1_161_844_396,
			3_125_318_951,
			1_431_517_754,
			  545_492_359,
			4_268_468_663,
			3_499_529_547,
			1_437_099_964,
			2_702_547_544,
			3_433_638_243,
			2_581_715_763,
			2_787_789_398,
			1_060_185_593,
			1_593_081_372,
			2_418_618_748,
			4_260_947_970,
			   69_676_912,
			2_159_744_348,
			   86_519_011,
			2_512_459_080,
			3_838_209_314,
			1_220_612_927,
			3_339_683_548,
			  133_810_670,
			1_090_789_135,
			1_078_426_020,
			1_569_222_167,
			  845_107_691,
			3_583_754_449,
			4_072_456_591,
			1_091_646_820,
			  628_848_692,
			1_613_405_280,
			3_757_631_651,
			  526_609_435,
			  236_106_946,
			   48_312_990,
			2_942_717_905,
			3_402_727_701,
			1_797_494_240,
			  859_738_849,
			  992_217_954,
			4_005_476_642,
			2_243_076_622,
			3_870_952_857,
			3_732_016_268,
			  765_654_824,
			3_490_871_365,
			2_511_836_413,
			1_685_915_746,
			3_888_969_200,
			1_414_112_111,
			2_273_134_842,
			3_281_911_079,
			4_080_962_846,
			  172_450_625,
			2_569_994_100,
			  980_381_355,
			4_109_958_455,
			2_819_808_352,
			2_716_589_560,
			2_568_741_196,
			3_681_446_669,
			3_329_971_472,
			1_835_478_071,
			  660_984_891,
			3_704_678_404,
			4_045_999_559,
			3_422_617_507,
			3_040_415_634,
			1_762_651_403,
			1_719_377_915,
			3_470_491_036,
			2_693_910_283,
			3_642_056_355,
			3_138_596_744,
			1_364_962_596,
			2_073_328_063,
			1_983_633_131,
			  926_494_387,
			3_423_689_081,
			2_150_032_023,
			4_096_667_949,
			1_749_200_295,
			3_328_846_651,
			  309_677_260,
			2_016_342_300,
			1_779_581_495,
			3_079_819_751,
			  111_262_694,
			1_274_766_160,
			  443_224_088,
			  298_511_866,
			1_025_883_608,
			3_806_446_537,
			1_145_181_785,
			  168_956_806,
			3_641_502_830,
			3_584_813_610,
			1_689_216_846,
			3_666_258_015,
			3_200_248_200,
			1_692_713_982,
			2_646_376_535,
			4_042_768_518,
			1_618_508_792,
			1_610_833_997,
			3_523_052_358,
			4_130_873_264,
			2_001_055_236,
			3_610_705_100,
			2_202_168_115,
			4_028_541_809,
			2_961_195_399,
			1_006_657_119,
			2_006_996_926,
			3_186_142_756,
			1_430_667_929,
			3_210_227_297,
			1_314_452_623,
			4_074_634_658,
			4_101_304_120,
			2_273_951_170,
			1_399_257_539,
			3_367_210_612,
			3_027_628_629,
			1_190_975_929,
			2_062_231_137,
			2_333_990_788,
			2_221_543_033,
			2_438_960_610,
			1_181_637_006,
			  548_689_776,
			2_362_791_313,
			3_372_408_396,
			3_104_550_113,
			3_145_860_560,
			  296_247_880,
			1_970_579_870,
			3_078_560_182,
			3_769_228_297,
			1_714_227_617,
			3_291_629_107,
			3_898_220_290,
			  166_772_364,
			1_251_581_989,
			  493_813_264,
			  448_347_421,
			  195_405_023,
			2_709_975_567,
			  677_966_185,
			3_703_036_547,
			1_463_355_134,
			2_715_995_803,
			1_338_867_538,
			1_343_315_457,
			2_802_222_074,
			2_684_532_164,
			  233_230_375,
			2_599_980_071,
			2_000_651_841,
			3_277_868_038,
			1_638_401_717,
			4_028_070_440,
			3_237_316_320,
			    6_314_154,
			  819_756_386,
			  300_326_615,
			  590_932_579,
			1_405_279_636,
			3_267_499_572,
			3_150_704_214,
			2_428_286_686,
			3_959_192_993,
			3_461_946_742,
			1_862_657_033,
			1_266_418_056,
			  963_775_037,
			2_089_974_820,
			2_263_052_895,
			1_917_689_273,
			  448_879_540,
			3_550_394_620,
			3_981_727_096,
			  150_775_221,
			3_627_908_307,
			1_303_187_396,
			  508_620_638,
			2_975_983_352,
			2_726_630_617,
			1_817_252_668,
			1_876_281_319,
			1_457_606_340,
			  908_771_278,
			3_720_792_119,
			3_617_206_836,
			2_455_994_898,
			1_729_034_894,
			1_080_033_504,
			  976_866_871,
			3_556_439_503,
			2_881_648_439,
			1_522_871_579,
			1_555_064_734,
			1_336_096_578,
			3_548_522_304,
			2_579_274_686,
			3_574_697_629,
			3_205_460_757,
			3_593_280_638,
			3_338_716_283,
			3_079_412_587,
			  564_236_357,
			2_993_598_910,
			1_781_952_180,
			1_464_380_207,
			3_163_844_217,
			3_332_601_554,
			1_699_332_808,
			1_393_555_694,
			1_183_702_653,
			3_581_086_237,
			1_288_719_814,
			  691_649_499,
			2_847_557_200,
			2_895_455_976,
			3_193_889_540,
			2_717_570_544,
			1_781_354_906,
			1_676_643_554,
			2_592_534_050,
			3_230_253_752,
			1_126_444_790,
			2_770_207_658,
			2_633_158_820,
			2_210_423_226,
			2_615_765_581,
			2_414_155_088,
			3_127_139_286,
			  673_620_729,
			2_805_611_233,
			1_269_405_062,
			4_015_350_505,
			3_341_807_571,
			4_149_409_754,
			1_057_255_273,
			2_012_875_353,
			2_162_469_141,
			2_276_492_801,
			2_601_117_357,
			  993_977_747,
			3_918_593_370,
			2_654_263_191,
			  753_973_209,
			   36_408_145,
			2_530_585_658,
			   25_011_837,
			3_520_020_182,
			2_088_578_344,
			  530_523_599,
			2_918_365_339,
			1_524_020_338,
			1_518_925_132,
			3_760_827_505,
			3_759_777_254,
			1_202_760_957,
			3_985_898_139,
			3_906_192_525,
			  674_977_740,
			4_174_734_889,
			2_031_300_136,
			2_019_492_241,
			3_983_892_565,
			4_153_806_404,
			3_822_280_332,
			  352_677_332,
			2_297_720_250,
			   60_907_813,
			   90_501_309,
			3_286_998_549,
			1_016_092_578,
			2_535_922_412,
			2_839_152_426,
			  457_141_659,
			  509_813_237,
			4_120_667_899,
			  652_014_361,
			1_966_332_200,
			2_975_202_805,
			   55_981_186,
			2_327_461_051,
			  676_427_537,
			3_255_491_064,
			2_882_294_119,
			3_433_927_263,
			1_307_055_953,
			  942_726_286,
			  933_058_658,
			2_468_411_793,
			3_933_900_994,
			4_215_176_142,
			1_361_170_020,
			2_001_714_738,
			2_830_558_078,
			3_274_259_782,
			1_222_529_897,
			1_679_025_792,
			2_729_314_320,
			3_714_953_764,
			1_770_335_741,
			  151_462_246,
			3_013_232_138,
			1_682_292_957,
			1_483_529_935,
			  471_910_574,
			1_539_241_949,
			  458_788_160,
			3_436_315_007,
			1_807_016_891,
			3_718_408_830,
			  978_976_581,
			1_043_663_428,
			3_165_965_781,
			1_927_990_952,
			4_200_891_579,
			2_372_276_910,
			3_208_408_903,
			3_533_431_907,
			1_412_390_302,
			2_931_980_059,
			4_132_332_400,
			1_947_078_029,
			3_881_505_623,
			4_168_226_417,
			2_941_484_381,
			1_077_988_104,
			1_320_477_388,
			  886_195_818,
			   18_198_404,
			3_786_409_000,
			2_509_781_533,
			  112_762_804,
			3_463_356_488,
			1_866_414_978,
			  891_333_506,
			   18_488_651,
			  661_792_760,
			1_628_790_961,
			3_885_187_036,
			3_141_171_499,
			  876_946_877,
			2_693_282_273,
			1_372_485_963,
			  791_857_591,
			2_686_433_993,
			3_759_982_718,
			3_167_212_022,
			3_472_953_795,
			2_716_379_847,
			  445_679_433,
			3_561_995_674,
			3_504_004_811,
			3_574_258_232,
			   54_117_162,
			3_331_405_415,
			2_381_918_588,
			3_769_707_343,
			4_154_350_007,
			1_140_177_722,
			4_074_052_095,
			  668_550_556,
			3_214_352_940,
			  367_459_370,
			  261_225_585,
			2_610_173_221,
			4_209_349_473,
			3_468_074_219,
			3_265_815_641,
			  314_222_801,
			3_066_103_646,
			3_808_782_860,
			  282_218_597,
			3_406_013_506,
			3_773_591_054,
			  379_116_347,
			1_285_071_038,
			  846_784_868,
			2_669_647_154,
			3_771_962_079,
			3_550_491_691,
			2_305_946_142,
			  453_669_953,
			1_268_987_020,
			3_317_592_352,
			3_279_303_384,
			3_744_833_421,
			2_610_507_566,
			3_859_509_063,
			  266_596_637,
			3_847_019_092,
			  517_658_769,
			3_462_560_207,
			3_443_424_879,
			  370_717_030,
			4_247_526_661,
			2_224_018_117,
			4_143_653_529,
			4_112_773_975,
			2_788_324_899,
			2_477_274_417,
			1_456_262_402,
			2_901_442_914,
			1_517_677_493,
			1_846_949_527,
			2_295_493_580,
			3_734_397_586,
			2_176_403_920,
			1_280_348_187,
			1_908_823_572,
			3_871_786_941,
			  846_861_322,
			1_172_426_758,
			3_287_448_474,
			3_383_383_037,
			1_655_181_056,
			3_139_813_346,
			  901_632_758,
			1_897_031_941,
			2_986_607_138,
			3_066_810_236,
			3_447_102_507,
			1_393_639_104,
			  373_351_379,
			  950_779_232,
			  625_454_576,
			3_124_240_540,
			4_148_612_726,
			2_007_998_917,
			  544_563_296,
			2_244_738_638,
			2_330_496_472,
			2_058_025_392,
			1_291_430_526,
			  424_198_748,
			   50_039_436,
			   29_584_100,
			3_605_783_033,
			2_429_876_329,
			2_791_104_160,
			1_057_563_949,
			3_255_363_231,
			3_075_367_218,
			3_463_963_227,
			1_469_046_755,
			  985_887_462
		};

		#endregion

		#region bcrypt IV: "OrpheanBeholderScryDoubt"

		private static readonly uint[] BfCryptCiphertext = {
			1_332_899_944,
			1_700_884_034,
			1_701_343_084,
			1_684_370_003,
			1_668_446_532,
			1_869_963_892
		};

		#endregion

		#region Table for Base64 encoding

		private static readonly char[] Base64Code = {
			'.',
			'/',
			'A',
			'B',
			'C',
			'D',
			'E',
			'F',
			'G',
			'H',
			'I',
			'J',
			'K',
			'L',
			'M',
			'N',
			'O',
			'P',
			'Q',
			'R',
			'S',
			'T',
			'U',
			'V',
			'W',
			'X',
			'Y',
			'Z',
			'a',
			'b',
			'c',
			'd',
			'e',
			'f',
			'g',
			'h',
			'i',
			'j',
			'k',
			'l',
			'm',
			'n',
			'o',
			'p',
			'q',
			'r',
			's',
			't',
			'u',
			'v',
			'w',
			'x',
			'y',
			'z',
			'0',
			'1',
			'2',
			'3',
			'4',
			'5',
			'6',
			'7',
			'8',
			'9'
		};

		#endregion

		#region Table for Base64 decoding

		private static readonly int[] Index64 = {
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			 0,
			 1,
			54,
			55,
			56,
			57,
			58,
			59,
			60,
			61,
			62,
			63,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			 2,
			 3,
			 4,
			 5,
			 6,
			 7,
			 8,
			 9,
			10,
			11,
			12,
			13,
			14,
			15,
			16,
			17,
			18,
			19,
			20,
			21,
			22,
			23,
			24,
			25,
			26,
			27,
			-1,
			-1,
			-1,
			-1,
			-1,
			-1,
			28,
			29,
			30,
			31,
			32,
			33,
			34,
			35,
			36,
			37,
			38,
			39,
			40,
			41,
			42,
			43,
			44,
			45,
			46,
			47,
			48,
			49,
			50,
			51,
			52,
			53,
			-1,
			-1,
			-1,
			-1,
			-1
		};

		#endregion

		#region Expanded Blowfish key

		private uint[] _p;

		private uint[] _s;

		#endregion

		/// <summary>Hash a string using the OpenBSD bcrypt scheme and a salt generated by <see cref="BCrypt.GenerateSalt()" /></summary>
		/// <remarks>Just an alias for HashPassword</remarks>
		/// <param name="source">The string to hash</param>
		/// <param name="saltSaltRevision">Allows you to override the salt revision used in the output</param>
		/// <returns>The hashed string</returns>
		public static string HashString(string source, SaltRevision saltSaltRevision = SaltRevision.Revision2B)
		{
			return HashPassword(source, saltSaltRevision);
		}

		/// <summary>Hash a string using the OpenBSD bcrypt scheme and a salt generated by <see cref="BCrypt.GenerateSalt()"/></summary>
		/// <remarks>Just an alias for HashPassword</remarks>
		/// <param name="source">The string to hash</param>
		/// <param name="workFactor">The log2 of the number of rounds of hashing to apply - the work factor therefore increases as 2^workFactor</param>
		/// <param name="saltSaltRevision">Allows you to override the salt revision used in the output</param>
		/// <returns>The hashed string.</returns>
		public static string HashString(string source, int workFactor, SaltRevision saltSaltRevision = SaltRevision.Revision2B)
		{
			return HashPassword(source, GenerateSalt(workFactor));
		}

		/// <summary>Hash a password using the OpenBSD bcrypt scheme and a salt generated by <see cref="BCrypt.GenerateSalt()"/></summary>
		/// <param name="input">The password to hash</param>
		/// <param name="saltSaltRevision">Allows you to override the salt revision used in the output</param>
		/// <returns>The hashed password</returns>
		public static string HashPassword(string input, SaltRevision saltSaltRevision = SaltRevision.Revision2B)
		{
			return HashPassword(input, GenerateSalt(saltSaltRevision));
		}

		/// <summary>Hash a password using the OpenBSD bcrypt scheme and a salt generated by <see cref="BCrypt.GenerateSalt(int)"/> using the given <paramref name="workFactor"/></summary>
		/// <param name="input">The password to hash</param>
		/// <param name="workFactor">The log2 of the number of rounds of hashing to apply - the work factor therefore increases as 2^workFactor</param>
		/// <param name="saltSaltRevision">Allows you to override the salt revision used in the output</param>
		/// <returns>The hashed password</returns>
		public static string HashPassword(string input, int workFactor, SaltRevision saltSaltRevision = SaltRevision.Revision2B)
		{
			return HashPassword(input, GenerateSalt(workFactor, saltSaltRevision));
		}

		/// <summary>Hash a password using the OpenBSD bcrypt scheme</summary>
		/// <exception cref="ArgumentException">Thrown when one or more arguments have unsupported or illegal values</exception>
		/// <param name="input">The password to hash</param>
		/// <param name="salt">the salt to hash with (perhaps generated using BCrypt.gensalt)</param>
		/// <returns>The hashed password</returns>
		public static string HashPassword(string input, string salt)
		{
			if (input == null) throw new ArgumentNullException(nameof(input));
			if (string.IsNullOrEmpty(salt)) throw new ArgumentException("Invalid salt", nameof(salt));
			// Determinthe starting offset and validate the salt
			int startingOffset;
			var minor = (char)0;
			if (salt[0] != '$' || salt[1] != '2') throw new SaltParseException("Invalid salt version");
			if (salt[2] == '$') startingOffset = 3;
			else
			{
				minor = salt[2];
				if (!(minor == 'a' || minor =='b' || minor=='x' || minor=='y') || salt[3] != '$') throw new SaltParseException("Invalid salt revision");
				startingOffset = 4;
			}
			// Extract number of rounds
			if (salt[startingOffset + 2] > '$') throw new SaltParseException("Missing salt rounds");
			// Extract details from salt
			var logRounds = Convert.ToInt32(salt.Substring(startingOffset, 2));
			var extractedSalt = salt.Substring(startingOffset + 3, 22);
			var inputBytes = Encoding.UTF8.GetBytes((input + (minor >= 'a' ? "\0" : "")));
			var saltBytes = DecodeBase64(extractedSalt, BcryptSaltLen);
			var bCrypt = new BCrypt();
			var hashed = bCrypt.CryptRaw(inputBytes, saltBytes, logRounds);
			// Generate result string
			var result = new StringBuilder();
			result.Append("$2");
			if (minor >= 'a') result.Append(minor);
			result.AppendFormat("${0:00}$", logRounds);
			result.Append(EncodeBase64(saltBytes, saltBytes.Length));
			result.Append(EncodeBase64(hashed, (BfCryptCiphertext.Length * 4) - 1));
			return result.ToString();
		}

		/// <summary>Generate a salt for use with the <see cref="BCrypt.HashPassword(string,string)"/> method</summary>
		/// <param name="workFactor">The log2 of the number of rounds of hashing to apply - the work factor therefore increases as 2**workFactor</param>
		/// <param name="saltSaltRevision">The revision to return in the salt portion, defaults to 2b</param>
		/// <returns>A base64 encoded salt value</returns>
		public static string GenerateSalt(int workFactor, SaltRevision saltSaltRevision = SaltRevision.Revision2B)
		{
			if (workFactor < 4 || workFactor > 31) throw new ArgumentOutOfRangeException(nameof(workFactor), workFactor, "The work factor must be between 4 and 31 (inclusive)");
			var rnd = new byte[BcryptSaltLen];
			var rng = RandomNumberGenerator.Create();
			rng.GetBytes(rnd);
			var rs = new StringBuilder();
			rs.AppendFormat("${0}${1:00}$", GetSaltRevisionString(saltSaltRevision), workFactor);
			rs.Append(EncodeBase64(rnd, rnd.Length));
			return rs.ToString();
		}

		/// <summary>Generate a salt for use with the <see cref="BCrypt.HashPassword(string,string)"/> method selecting a reasonable default for the number of hashing rounds to apply</summary>
		/// <param name="saltSaltRevision">The revision to return in the salt portion, defaults to 2b</param>
		/// <returns>A base64 encoded salt value</returns>
		public static string GenerateSalt(SaltRevision saltSaltRevision = SaltRevision.Revision2B)
		{
			return GenerateSalt(GensaltDefaultLog2Rounds, saltSaltRevision);
		}

		/// <summary>Verifies that the hash of the given <paramref name="text"/> matches the provided <paramref name="hash"/></summary>
		/// <param name="text">The text to verify</param>
		/// <param name="hash">The previously-hashed password</param>
		/// <returns>true if the passwords match, false otherwise</returns>
		public static bool Verify(string text, string hash)
		{
			return SafeEquals(hash, HashPassword(text, hash));
		}

		/// <summary>Returns work factor from the generated hash</summary>
		/// <param name="hashedPassword"></param>
		/// <returns></returns>
		public static int GetPasswordWorkFactor(string hashedPassword)
		{
			if (string.IsNullOrEmpty(hashedPassword)) throw new ArgumentNullException(nameof(hashedPassword), "Invalid password");
			if (hashedPassword.Length < 7) throw new ArgumentException("Invalid password", nameof(hashedPassword));
			if (hashedPassword[0] != '$' || hashedPassword[1] != '2') throw new SaltParseException("Invalid salt version");
			/*
			We assume any hashed password should have one of these prefixes, otherwise we throw an exception
			SaltRevision.Revision2 = "$2$"
			SaltRevision.Revision2A = "$2a$"
			SaltRevision.Revision2B = "$2b$"
			SaltRevision.Revision2X = "$2x$"
			SaltRevision.Revision2Y = "$2y$"
			A password sample: $2b$10$TwentytwocharactersaltThirtyonecharacterspasswordhash
			$==$==$======================-------------------------------
			*/
			var workFactorStartIndex = GetWorkFactorStartIndex(hashedPassword);
			// If the followed character after work factor is not $, then it might be some invalid hash
			if (hashedPassword[workFactorStartIndex + 2] != '$') throw new InvalidDataException("Missing salt rounds");
			var result = int.Parse(hashedPassword.Substring(workFactorStartIndex, 2));
			return result;
		}

		/// <summary>Encode a byte array using bcrypt's slightly-modified base64 encoding scheme. Note that this is *not* compatible with the standard MIME-base64 encoding.</summary>
		/// <exception cref="ArgumentException">Thrown when one or more arguments have unsupported or illegal values</exception>
		/// <param name="byteArray">The byte array to encode</param>
		/// <param name="length">The number of bytes to encode</param>
		/// <returns>Base64-encoded string</returns>
		private static string EncodeBase64(byte[] byteArray, int length)
		{
			if (length <= 0 || length > byteArray.Length) throw new ArgumentException("Invalid length", nameof(length));
			var off = 0;
			var rs = new StringBuilder();
			while (off < length)
			{
				var c1 = byteArray[off++] & 0xff;
				rs.Append(Base64Code[(c1 >> 2) & 0x3f]);
				c1 = (c1 & 0x03) << 4;
				if (off >= length)
				{
					rs.Append(Base64Code[c1 & 0x3f]);
					break;
				}
				var c2 = byteArray[off++] & 0xff;
				c1 |= (c2 >> 4) & 0x0f;
				rs.Append(Base64Code[c1 & 0x3f]);
				c1 = (c2 & 0x0f) << 2;
				if (off >= length)
				{
					rs.Append(Base64Code[c1 & 0x3f]);
					break;
				}
				c2 = byteArray[off++] & 0xff;
				c1 |= (c2 >> 6) & 0x03;
				rs.Append(Base64Code[c1 & 0x3f]);
				rs.Append(Base64Code[c2 & 0x3f]);
			}
			return rs.ToString();
		}

		/// <summary>Decode a string encoded using bcrypt's base64 scheme to a byte array. Note that this is *not* compatible with the standard MIME-base64 encoding.</summary>
		/// <exception cref="ArgumentException">Thrown when one or more arguments have unsupported or illegal values</exception>
		/// <param name="encodedstring">The string to decode</param>
		/// <param name="maximumBytes">The maximum bytes to decode</param>
		/// <returns>The decoded byte array</returns>
		private static byte[] DecodeBase64(string encodedstring, int maximumBytes)
		{
			var position = 0;
			var sourceLength = encodedstring.Length;
			var outputLength = 0;
			if (maximumBytes <= 0) throw new ArgumentException("Invalid maximum bytes value", nameof(maximumBytes));
			// TODO: update to use a List<byte> - it's only ever 16 bytes, so it's not a big deal
			var rs = new StringBuilder();
			while (position < sourceLength - 1 && outputLength < maximumBytes)
			{
				var c1 = Char64(encodedstring[position++]);
				var c2 = Char64(encodedstring[position++]);
				if (c1 == -1 || c2 == -1) break;
				rs.Append((char)((c1 << 2) | ((c2 & 0x30) >> 4)));
				if (++outputLength >= maximumBytes || position >= sourceLength) break;
				var c3 = Char64(encodedstring[position++]);
				if (c3 == -1) break;
				rs.Append((char)(((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2)));
				if (++outputLength >= maximumBytes || position >= sourceLength) break;
				var c4 = Char64(encodedstring[position++]);
				rs.Append((char)(((c3 & 0x03) << 6) | c4));
				++outputLength;
			}
			var ret = new byte[outputLength];
			for (position = 0; position < outputLength; position++) ret[position] = (byte)rs[position];
			return ret;
		}

		/// <summary>Look up the 3 bits base64-encoded by the specified character, range-checking against conversion table</summary>
		/// <param name="character">The base64-encoded value</param>
		/// <returns>The decoded value of x</returns>
		private static int Char64(char character)
		{
			if (character < 0 || character > Index64.Length) return -1;
			return Index64[character];
		}

		/// <summary>Blowfish encipher a single 64-bit block encoded as two 32-bit halves</summary>
		/// <param name="blockArray">An array containing the two 32-bit half blocks</param>
		/// <param name="offset">The position in the array of the blocks</param>
		private void Encipher(uint[] blockArray, int offset)
		{
			var block = blockArray[offset];
			var r = blockArray[offset + 1];
			block ^= _p[0];
			unchecked
			{
				uint round;
				for (round = 0; round <= BlowfishNumRounds - 2; )
				{
					// Feistel substitution on left word
					var n = _s[(block >> 24) & 0xff];
					n += _s[0x100 | ((block >> 16) & 0xff)];
					n ^= _s[0x200 | ((block >> 8) & 0xff)];
					n += _s[0x300 | (block & 0xff)];
					r ^= n ^ _p[++round];
					// Feistel substitution on right word
					n = _s[(r >> 24) & 0xff];
					n += _s[0x100 | ((r >> 16) & 0xff)];
					n ^= _s[0x200 | ((r >> 8) & 0xff)];
					n += _s[0x300 | (r & 0xff)];
					block ^= n ^ _p[++round];
				}
				blockArray[offset] = r ^ _p[BlowfishNumRounds + 1];
				blockArray[offset + 1] = block;
			}
		}

		/// <summary>Cycically extract a word of key material.</summary>
		/// <param name="data">The string to extract the data from.</param>
		/// <param name="offset"> [in,out] The current offset.</param>
		/// <returns>The next word of material from data.</returns>
		private static uint StreamToWord(byte[] data, ref int offset)
		{
			int i;
			uint word = 0;
			for (i = 0; i < 4; i++)
			{
				word = (word << 8) | (uint)(data[offset] & 0xff);
				offset = (offset + 1) % data.Length;
			}
			return word;
		}

		/// <summary>Initializes the Blowfish key schedule</summary>
		private void InitializeKey()
		{
			_p = new uint[POrig.Length];
			_s = new uint[SOrig.Length];
			Array.Copy(POrig, _p, POrig.Length);
			Array.Copy(SOrig, _s, SOrig.Length);
		}

		/// <summary>Key the Blowfish cipher</summary>
		/// <param name="keyBytes">The key byte array</param>
		private void Key(byte[] keyBytes)
		{
			int i;
			var koffp = 0;
			uint[] lr = { 0, 0 };
			int plen = _p.Length, slen = _s.Length;
			for (i = 0; i < plen; i++) _p[i] = _p[i] ^ StreamToWord(keyBytes, ref koffp);
			for (i = 0; i < plen; i += 2)
			{
				Encipher(lr, 0);
				_p[i] = lr[0];
				_p[i + 1] = lr[1];
			}
			for (i = 0; i < slen; i += 2)
			{
				Encipher(lr, 0);
				_s[i] = lr[0];
				_s[i + 1] = lr[1];
			}
		}

		/// <summary>Perform the "enhanced key schedule" step described by Provos and Mazieres in "A Future-Adaptable Password Scheme" http://www.openbsd.org/papers/bcrypt-paper.ps.</summary>
		/// <param name="saltBytes">Salt byte array</param>
		/// <param name="inputBytes">Input byte array</param>
		private void EksKey(byte[] saltBytes, byte[] inputBytes)
		{
			int i;
			var passwordOffset = 0;
			var saltOffset = 0;
			uint[] lr = { 0, 0 };
			int plen = _p.Length, slen = _s.Length;
			for (i = 0; i < plen; i++) _p[i] = _p[i] ^ StreamToWord(inputBytes, ref passwordOffset);
			for (i = 0; i < plen; i += 2)
			{
				lr[0] ^= StreamToWord(saltBytes, ref saltOffset);
				lr[1] ^= StreamToWord(saltBytes, ref saltOffset);
				Encipher(lr, 0);
				_p[i] = lr[0];
				_p[i + 1] = lr[1];
			}
			for (i = 0; i < slen; i += 2)
			{
				lr[0] ^= StreamToWord(saltBytes, ref saltOffset);
				lr[1] ^= StreamToWord(saltBytes, ref saltOffset);
				Encipher(lr, 0);
				_s[i] = lr[0];
				_s[i + 1] = lr[1];
			}
		}

		/// <summary>Perform the central hashing step in the bcrypt scheme</summary>
		/// <exception cref="ArgumentException">Thrown when one or more arguments have unsupported or illegal values</exception>
		/// <param name="inputBytes">The input byte array to hash</param>
		/// <param name="saltBytes">The salt byte array to hash with</param>
		/// <param name="logRounds">The binary logarithm of the number of rounds of hashing to apply</param>
		/// <returns>A byte array containing the hashed result</returns>
		private byte[] CryptRaw(byte[] inputBytes, byte[] saltBytes, int logRounds)
		{
			var cdata = new uint[BfCryptCiphertext.Length];
			Array.Copy(BfCryptCiphertext, cdata, BfCryptCiphertext.Length);
			var clen = cdata.Length;
			if (logRounds < 4 || logRounds > 31) throw new ArgumentException("Bad number of rounds", nameof(logRounds));
			var rounds = 1u << logRounds;
			// We overflowed rounds at 31 - added safety check
			if (!(rounds > 0)) throw new ArgumentException("Rounds must be > 0", nameof(logRounds));
			if (saltBytes.Length != BcryptSaltLen) throw new ArgumentException("Bad salt Length", nameof(saltBytes));
			InitializeKey();
			EksKey(saltBytes, inputBytes);
			for (var i = 0; i < rounds; i++)
			{
				Key(inputBytes);
				Key(saltBytes);
			}
			for (var i = 0; i < 64; i++) for (var j = 0; j < clen >> 1; j++) Encipher(cdata, j << 1);
			var ret = new byte[clen * 4];
			for (int i = 0, j = 0; i < clen; i++)
			{
				ret[j++] = (byte)((cdata[i] >> 24) & 0xff);
				ret[j++] = (byte)((cdata[i] >> 16) & 0xff);
				ret[j++] = (byte)((cdata[i] >> 8) & 0xff);
				ret[j++] = (byte)(cdata[i] & 0xff);
			}
			return ret;
		}

		/// <summary>Checks if two strings are equal. Compares every char to prevent timing attacks.</summary>
		/// <param name="a">String to compare</param>
		/// <param name="b">String to compare</param>
		/// <returns>True if both strings are equal</returns>
		private static bool SafeEquals(string a, string b)
		{
			var diff = (uint) a.Length ^ (uint) b.Length;
			for (var i = 0; i < a.Length && i < b.Length; i++) diff |= a[i] ^ (uint) b[i];
			return diff == 0;
		}

		/// <summary>Gets the string representation of the salt revision</summary>
		/// <param name="saltSaltRevision">Salt revision enum</param>
		/// <returns>The string representation of the salt revision</returns>
		private static string GetSaltRevisionString(SaltRevision saltSaltRevision)
		{
			switch (saltSaltRevision)
			{
				case SaltRevision.Revision2:
					return "2";
				case SaltRevision.Revision2A:
					return "2a";
				case SaltRevision.Revision2B:
					return "2b";
				case SaltRevision.Revision2X:
					return "2x";
				case SaltRevision.Revision2Y:
					return "2y";
				default:
					throw new ArgumentOutOfRangeException(nameof(saltSaltRevision), saltSaltRevision, null);
			}
		}

		/// <summary>Return starting index of a work factor from a hashed password</summary>
		/// <param name="hash"></param>
		/// <returns></returns>
		private static int GetWorkFactorStartIndex(string hash)
		{
			var uniqueIdentifier = hash[2];
			switch (uniqueIdentifier)
			{
				case '$':
					return 3;
				case 'a':
				case 'b':
				case 'x':
				case 'y':
					return 4;
				default:
					throw new SaltParseException("Invalid salt revision");
			}
		}

	}

	#endregion

}
