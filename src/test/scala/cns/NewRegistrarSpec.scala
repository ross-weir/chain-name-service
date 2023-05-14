package cns

import cns.Constants.{newRegistrarNft, newRegistrarScript, registryAdminNft, registryScript}
import io.getblok.getblok_plasma.ByteConversion.{convertsArrBytes, convertsString}
import io.getblok.getblok_plasma.PlasmaParameters
import io.getblok.getblok_plasma.collections.PlasmaMap
import org.ergoplatform.{ErgoAddressEncoder, P2PKAddress}
import org.ergoplatform.ErgoAddressEncoder.TestnetNetworkPrefix
import org.ergoplatform.appkit._
import org.ergoplatform.wallet.secrets.ExtendedSecretKey
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should
import scorex.crypto.hash.Blake2b256
import sigmastate.AvlTreeFlags
import sigmastate.lang.exceptions.InterpreterException

class NewRegistrarSpec extends AnyFlatSpec with should.Matchers {
  val ergoClient: ErgoClient = RestApiErgoClient.create("http://127.0.0.1:9052/", NetworkType.TESTNET, "", "")
  val addrEnc = new ErgoAddressEncoder(NetworkType.TESTNET.networkPrefix)
  val fakeIndex: Short = 1
  val fakeTxId1 = "f9e5ce5aa0d95f5d54a7bc89c46730d9662397067250aa18a0039631c0f5b809"
  val fakeTxId2 = "f9e5ce5aa0d95f5d54a7bc89c46730d9662397067250aa18a0039631c0f5b808"
  val fakeTxId3 = "f9e5ce5aa0d95f5d54a7bc89c46730d9662397067250aa18a0039631c0f5b807"
  val fakeTxId4 = "f9e5ce5aa0d95f5d54a7bc89c46730d9662397067250aa18a0039631c0f5b806"
  val fakeTxId5 = "f9e5ce5aa0d95f5d54a7bc89c46730d9662397067250aa18a0039631c0f5b105"
  val changeAddress = "9gQqZyxyjAptMbfW1Gydm3qaap11zd6X9DrABwgEE9eRdRvd27p"
  val fakeScript = "sigmaProp(true)"
  lazy val minStorageRent = 100000L

  "RandomTest" should "dothing" in {
    val script =
      s"""{
         |  val scriptHash = SELF.R4[Coll[Byte]].get
         |
         |  sigmaProp(blake2b256(OUTPUTS(0).propositionBytes) == scriptHash)
         |}""".stripMargin

    ergoClient.execute(ctx => {
      val mnemonic = SecretString.create("not real mnemonic")
      val rootSecret = JavaHelpers.seedToMasterKey(mnemonic, SecretString.empty(), true)
      val path = JavaHelpers.eip3DerivationParent
      val secretKey = rootSecret.derive(path).asInstanceOf[ExtendedSecretKey]

      implicit val encoder: ErgoAddressEncoder = ErgoAddressEncoder(ErgoAddressEncoder.TestnetNetworkPrefix)
      val p2pk = P2PKAddress(secretKey.publicImage)
      val p2pkContract = ctx.newContract(p2pk.script)

      val prover = ctx.newProverBuilder()
        .withDLogSecret(BigInt.apply(0).bigInteger)
        .withDLogSecret(secretKey.privateInput.w)
        .build()

//      val addr = Address.create("")
//      val p2pkContract = Address.create("").toErgoContract

      val tb = ctx.newTxBuilder()

      val compiledScript = Utils.compile(Map.empty, script, TestnetNetworkPrefix)
      val bytes = compiledScript.bytes
      val hashedScript = Blake2b256.hash(bytes)

      val adminBox =
        tb
          .outBoxBuilder
          .value(minStorageRent)
          .tokens(new ErgoToken("94af8793a1f7b427831dcb48368ffc55c68d319d525ea24510ac38b75e280a8d", 1)) // incorrect token id
          .contract(p2pkContract)
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)

      val inBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .registers(ErgoValue.of(hashedScript))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), fakeScript))
          .build()
          .convertToInputWith("f9e5ce5aa0d95f5d54a7bc89c46730d9662397067250aa18a0039631c0f5b807", 1)

      val outBox =
        tb
          .outBoxBuilder()
          .contract(ctx.compileContract(ConstantsBuilder.empty(), fakeScript))
          .build()

      val tx = tb
        .fee(1e7.toLong)
        .addInputs(inBox, adminBox)
        .addOutputs(outBox)
//        .addDataInputs(adminBox)
        .sendChangeTo(Address.create("4MQyML64GnzMxZgm"))
        .build()

      val _ = prover.sign(tx)

      println("success")
    })
  }

  "NewRegistrar" should "fail if RegistryAdmin data input is missing" in {
    ergoClient.execute(ctx => {
      val prover = ctx.newProverBuilder()
        .withDLogSecret(BigInt.apply(0).bigInteger)
        .build()

      // coll[byte] -> byte (blake2b256(tld) -> 1)
      val registrarsMap = new PlasmaMap[Array[Byte], String](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      // coll[byte] -> ErgoId (hashed name -> nft)
      val resolversMap = new PlasmaMap[Array[Byte], ErgoId](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      val tldToMint = "erg"
      val hashedTld = Blake2b256.hash(tldToMint)

      val tb = ctx.newTxBuilder()

      val registryInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()
          .convertToInputWith(fakeTxId3, fakeIndex)

      var newRegistrarInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .tokens(new ErgoToken(newRegistrarNft, 1))
          .registers(ErgoValue.of(tldToMint.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), newRegistrarScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)
      val updatedRegistrarsMapResult = registrarsMap.insert((hashedTld, "01"))
      newRegistrarInBox = newRegistrarInBox.withContextVars(new ContextVar(0.toByte, updatedRegistrarsMapResult.proof.ergoValue))

      val registryOutBox =
        tb
          .outBoxBuilder()
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()

      val newRegistrarOutBox =
        tb
          .outBoxBuilder
          .tokens(new ErgoToken(newRegistrarNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), newRegistrarScript))
          .build()

      val tx = tb
        .fee(1e7.toLong)
        .addInputs(registryInBox, newRegistrarInBox)
        .addOutputs(registryOutBox, newRegistrarOutBox)
        .sendChangeTo(Address.create("4MQyML64GnzMxZgm"))
        .build()

      // attempted to index CONTEXT.dataInputs(0)
      an [ArrayIndexOutOfBoundsException] should be thrownBy prover.sign(tx)
    })
  }

  "NewRegistrar" should "fail if RegistryAdmin data input has incorrect nft" in {
    ergoClient.execute(ctx => {
      val prover = ctx.newProverBuilder()
        .withDLogSecret(BigInt.apply(0).bigInteger)
        .build()

      // coll[byte] -> byte (blake2b256(tld) -> 1)
      val registrarsMap = new PlasmaMap[Array[Byte], String](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      // coll[byte] -> ErgoId (hashed name -> nft)
      val resolversMap = new PlasmaMap[Array[Byte], ErgoId](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      val tldToMint = "erg"
      val hashedTld = Blake2b256.hash(tldToMint)

      val tb = ctx.newTxBuilder()

      val adminBox =
        tb
          .outBoxBuilder
          .value(minStorageRent)
          .tokens(new ErgoToken("94af8793a1f7b427831dcb48368ffc55c68d319d525ea24510ac38b75e280a8d", 1)) // incorrect token id
          .contract(ctx.compileContract(ConstantsBuilder.empty(), fakeScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)

      val registryInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()
          .convertToInputWith(fakeTxId3, fakeIndex)

      var newRegistrarInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .tokens(new ErgoToken(newRegistrarNft, 1))
          .registers(ErgoValue.of(tldToMint.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), newRegistrarScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)
      val updatedRegistrarsMapResult = registrarsMap.insert((hashedTld, "01"))
      newRegistrarInBox = newRegistrarInBox.withContextVars(new ContextVar(0.toByte, updatedRegistrarsMapResult.proof.ergoValue))

      val registryOutBox =
        tb
          .outBoxBuilder()
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()

      val newRegistrarOutBox =
        tb
          .outBoxBuilder
          .tokens(new ErgoToken(newRegistrarNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), newRegistrarScript))
          .build()

      val adminOutBox =
        tb
          .outBoxBuilder
          .value(minStorageRent)
          .tokens(new ErgoToken("94af8793a1f7b427831dcb48368ffc55c68d319d525ea24510ac38b75e280a8d", 1)) // incorrect token id
          .contract(ctx.compileContract(ConstantsBuilder.empty(), fakeScript))
          .build()

      val tx = tb
        .fee(1e7.toLong)
        .addInputs(registryInBox, newRegistrarInBox, adminBox)
        .addOutputs(registryOutBox, newRegistrarOutBox, adminOutBox)
        .sendChangeTo(Address.create("4MQyML64GnzMxZgm"))
        .build()

      (the [InterpreterException] thrownBy prover.sign(tx)).getMessage should be("Script reduced to false")
    })
  }

  "NewRegistrar" should "fail if registrars state in Registry isn't updated correctly" in {
    ergoClient.execute(ctx => {
      val prover = ctx.newProverBuilder()
        .withDLogSecret(BigInt.apply(0).bigInteger)
        .build()

      // coll[byte] -> byte (blake2b256(tld) -> 1)
      val registrarsMap = new PlasmaMap[Array[Byte], String](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      // coll[byte] -> ErgoId (hashed name -> nft)
      val resolversMap = new PlasmaMap[Array[Byte], ErgoId](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      val tldToMint = "erg"

      val tb = ctx.newTxBuilder()

      val adminBox =
        tb
          .outBoxBuilder
          .value(minStorageRent)
          .tokens(new ErgoToken(registryAdminNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), fakeScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)

      val registryInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()
          .convertToInputWith(fakeTxId3, fakeIndex)

      var newRegistrarInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .tokens(new ErgoToken(newRegistrarNft, 1))
          .registers(ErgoValue.of(tldToMint.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), newRegistrarScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)
      // insert a different name than that in the register
      val updatedRegistrarsMapResult = registrarsMap.insert((Blake2b256.hash("noterg"), "01"))
      newRegistrarInBox = newRegistrarInBox.withContextVars(new ContextVar(0.toByte, updatedRegistrarsMapResult.proof.ergoValue))

      val registryOutBox =
        tb
          .outBoxBuilder()
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()

      val newRegistrarOutBox =
        tb
          .outBoxBuilder
          .tokens(new ErgoToken(newRegistrarNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), newRegistrarScript))
          .build()

      val adminOutBox =
        tb
          .outBoxBuilder
          .value(minStorageRent)
          .tokens(new ErgoToken(registryAdminNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), fakeScript))
          .build()

      val tx = tb
        .fee(1e7.toLong)
        .addInputs(registryInBox, newRegistrarInBox, adminBox)
        .addOutputs(registryOutBox, newRegistrarOutBox, adminOutBox)
        .sendChangeTo(Address.create("4MQyML64GnzMxZgm"))
        .build()

      (the[InterpreterException] thrownBy prover.sign(tx)).getMessage should be("Script reduced to false")
    })
  }

  "NewRegistrar" should "fail if successor script changed" in {
    ergoClient.execute(ctx => {
      val prover = ctx.newProverBuilder()
        .withDLogSecret(BigInt.apply(0).bigInteger)
        .build()

      // coll[byte] -> byte (blake2b256(tld) -> 1)
      val registrarsMap = new PlasmaMap[Array[Byte], String](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      // coll[byte] -> ErgoId (hashed name -> nft)
      val resolversMap = new PlasmaMap[Array[Byte], ErgoId](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      val tldToMint = "erg"
      val hashedTld = Blake2b256.hash(tldToMint)

      val tb = ctx.newTxBuilder()

      val adminBox =
        tb
          .outBoxBuilder
          .value(minStorageRent)
          .tokens(new ErgoToken(registryAdminNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), fakeScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)

      val registryInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()
          .convertToInputWith(fakeTxId3, fakeIndex)

      var newRegistrarInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .tokens(new ErgoToken(newRegistrarNft, 1))
          .registers(ErgoValue.of(tldToMint.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), newRegistrarScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)
      val updatedRegistrarsMapResult = registrarsMap.insert((hashedTld, "01"))
      newRegistrarInBox = newRegistrarInBox.withContextVars(new ContextVar(0.toByte, updatedRegistrarsMapResult.proof.ergoValue))

      val registryOutBox =
        tb
          .outBoxBuilder()
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()

      val newRegistrarOutBox =
        tb
          .outBoxBuilder
          .tokens(new ErgoToken(newRegistrarNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), fakeScript))
          .build()

      val adminOutBox =
        tb
          .outBoxBuilder
          .value(minStorageRent)
          .tokens(new ErgoToken(registryAdminNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), fakeScript))
          .build()

      val tx = tb
        .fee(1e7.toLong)
        .addInputs(registryInBox, newRegistrarInBox, adminBox)
        .addOutputs(registryOutBox, newRegistrarOutBox, adminOutBox)
        .sendChangeTo(Address.create("4MQyML64GnzMxZgm"))
        .build()

      (the[InterpreterException] thrownBy prover.sign(tx)).getMessage should be("Script reduced to false")
    })
  }

  "NewRegistrar" should "add new registrar to Registry" in {
    ergoClient.execute(ctx => {
      val prover = ctx.newProverBuilder()
        .withDLogSecret(BigInt.apply(0).bigInteger)
        .build()

      // coll[byte] -> byte (blake2b256(tld) -> 1)
      val registrarsMap = new PlasmaMap[Array[Byte], String](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      // coll[byte] -> ErgoId (hashed name -> nft)
      val resolversMap = new PlasmaMap[Array[Byte], ErgoId](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      val tldToMint = "erg"
      val hashedTld = Blake2b256.hash(tldToMint)

      val tb = ctx.newTxBuilder()

      val adminBox =
          tb
          .outBoxBuilder
          .value(minStorageRent)
          .tokens(new ErgoToken(registryAdminNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), fakeScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)

      val registryInBox =
          tb
          .outBoxBuilder
            .value(100000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()
          .convertToInputWith(fakeTxId3, fakeIndex)

      var newRegistrarInBox =
          tb
          .outBoxBuilder
            .value(100000000000000000L)
          .tokens(new ErgoToken(newRegistrarNft, 1))
          .registers(ErgoValue.of(tldToMint.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), newRegistrarScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)
      val updatedRegistrarsMapResult = registrarsMap.insert((hashedTld, "01"))
      newRegistrarInBox = newRegistrarInBox.withContextVars(new ContextVar(0.toByte, updatedRegistrarsMapResult.proof.ergoValue))

      val registryOutBox =
          tb
          .outBoxBuilder()
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()

      val newRegistrarOutBox =
          tb
          .outBoxBuilder
          .tokens(new ErgoToken(newRegistrarNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), newRegistrarScript))
          .build()

      val adminOutBox =
        tb
          .outBoxBuilder
          .value(minStorageRent)
          .tokens(new ErgoToken(registryAdminNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), fakeScript))
          .build()

      val tx = tb
        .fee(1e7.toLong)
        .addInputs(registryInBox, newRegistrarInBox, adminBox)
        .addOutputs(registryOutBox, newRegistrarOutBox, adminOutBox)
        .sendChangeTo(Address.create("4MQyML64GnzMxZgm"))
        .build()

      noException should be thrownBy prover.sign(tx)
    })
  }
}