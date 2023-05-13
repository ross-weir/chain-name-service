package cns

import cns.Constants.{mintResolverNft, mintResolverScript, registryScript, resolverScript}
import io.getblok.getblok_plasma.PlasmaParameters
import io.getblok.getblok_plasma.collections.PlasmaMap
import io.getblok.getblok_plasma.ByteConversion.{convertsArrBytes, convertsString}
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should
import org.ergoplatform.ErgoAddressEncoder
import org.ergoplatform.appkit.{Address, ConstantsBuilder, ContextVar, ErgoClient, ErgoId, ErgoToken, ErgoValue, JavaHelpers, NetworkType, RestApiErgoClient, SecretString}
import org.ergoplatform.wallet.secrets.ExtendedSecretKey
import sigmastate.AvlTreeFlags
import scorex.crypto.hash.Blake2b256
import sigmastate.eval.CostingSigmaDslBuilder.GroupElement
import sigmastate.lang.exceptions.InterpreterException

class MintResolverSpec extends AnyFlatSpec with should.Matchers {
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
  val mnemonic = SecretString.create("not real mnemonic")
  val rootSecret = JavaHelpers.seedToMasterKey(mnemonic, SecretString.empty(), true)
  val path = JavaHelpers.eip3DerivationParent
  val secretKey = rootSecret.derive(path).asInstanceOf[ExtendedSecretKey]
  val pkGe = GroupElement(secretKey.publicImage.value)

  "MintResolver" should "fail if tld doesn't exist" in {
    ergoClient.execute(ctx => {
      val prover = ctx.newProverBuilder()
        .withDLogSecret(secretKey.privateInput.w)
        .build()

      // coll[byte] -> byte (blake2b256(tld) -> 1)
      val registrarsMap = new PlasmaMap[Array[Byte], String](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      // coll[byte] -> ErgoId (hashed name -> nft)
      val resolversMap = new PlasmaMap[Array[Byte], ErgoId](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)

      val tld = "erg"
      val label = "hello"
      val resolvedToAddress = "4MQyML64GnzMxZgm"
      val tldHash = Blake2b256.hash(tld)

      val _ = registrarsMap.insert((tldHash, "01"))
      val containsOp = registrarsMap.lookUp(tldHash)

      val tb = ctx.newTxBuilder()

      val registryInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()
          .convertToInputWith(fakeTxId3, fakeIndex)

      var mintResolverBox =
        tb
          .outBoxBuilder
          .value(500000000000000000L)
          .tokens(new ErgoToken(mintResolverNft, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of("non".getBytes), ErgoValue.of(resolvedToAddress.getBytes)) // changed tld to "non"
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)
      val insertLabel = resolversMap.insert((Blake2b256.hash(label ++ tld), registryInBox.getId))
      mintResolverBox = mintResolverBox.withContextVars(
        new ContextVar(0.toByte, containsOp.proof.ergoValue),
        new ContextVar(1.toByte, insertLabel.proof.ergoValue))

      val registryOutBox =
        tb
          .outBoxBuilder()
          .value(200000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()

      val mintResolverOutBox =
        tb
          .outBoxBuilder
          .tokens(new ErgoToken(mintResolverNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()

      val resolverOutBox =
        tb
          .outBoxBuilder()
          .tokens(new ErgoToken(registryInBox.getId, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), resolverScript))
          .build()

      val tx = tb
        .fee(1e7.toLong)
        .addInputs(registryInBox, mintResolverBox)
        .addOutputs(registryOutBox, mintResolverOutBox, resolverOutBox)
        .sendChangeTo(Address.create("4MQyML64GnzMxZgm"))
        .build()

      (the[InterpreterException] thrownBy prover.sign(tx)).getMessage should be("Script reduced to false")
    })
  }

  "MintResolver" should "fail if label is too long" in {
    ergoClient.execute(ctx => {
      val prover = ctx.newProverBuilder()
        .withDLogSecret(secretKey.privateInput.w)
        .build()

      // coll[byte] -> byte (blake2b256(tld) -> 1)
      val registrarsMap = new PlasmaMap[Array[Byte], String](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      // coll[byte] -> ErgoId (hashed name -> nft)
      val resolversMap = new PlasmaMap[Array[Byte], ErgoId](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)

      val tld = "erg"
      val label = "helloworldhelloworldhelloworldhelloworldhelloworld"
      val resolvedToAddress = "4MQyML64GnzMxZgm"
      val tldHash = Blake2b256.hash(tld)

      val _ = registrarsMap.insert((tldHash, "01"))
      val containsOp = registrarsMap.lookUp(tldHash)

      val tb = ctx.newTxBuilder()

      val registryInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()
          .convertToInputWith(fakeTxId3, fakeIndex)

      var mintResolverBox =
        tb
          .outBoxBuilder
          .value(500000000000000000L)
          .tokens(new ErgoToken(mintResolverNft, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)
      val insertLabel = resolversMap.insert((Blake2b256.hash(label ++ tld), registryInBox.getId))
      mintResolverBox = mintResolverBox.withContextVars(
        new ContextVar(0.toByte, containsOp.proof.ergoValue),
        new ContextVar(1.toByte, insertLabel.proof.ergoValue))

      val registryOutBox =
        tb
          .outBoxBuilder()
          .value(200000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()

      val mintResolverOutBox =
        tb
          .outBoxBuilder
          .tokens(new ErgoToken(mintResolverNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()

      val resolverOutBox =
        tb
          .outBoxBuilder()
          .tokens(new ErgoToken(registryInBox.getId, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), resolverScript))
          .build()

      val tx = tb
        .fee(1e7.toLong)
        .addInputs(registryInBox, mintResolverBox)
        .addOutputs(registryOutBox, mintResolverOutBox, resolverOutBox)
        .sendChangeTo(Address.create("4MQyML64GnzMxZgm"))
        .build()

      (the[InterpreterException] thrownBy prover.sign(tx)).getMessage should be("Script reduced to false")
    })
  }

  "MintResolver" should "fail if Resolver out box has wrong script" in {
    ergoClient.execute(ctx => {
      val prover = ctx.newProverBuilder()
        .withDLogSecret(secretKey.privateInput.w)
        .build()

      // coll[byte] -> byte (blake2b256(tld) -> 1)
      val registrarsMap = new PlasmaMap[Array[Byte], String](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      // coll[byte] -> ErgoId (hashed name -> nft)
      val resolversMap = new PlasmaMap[Array[Byte], ErgoId](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)

      val tld = "erg"
      val label = "helloworld"
      val resolvedToAddress = "4MQyML64GnzMxZgm"
      val tldHash = Blake2b256.hash(tld)

      val _ = registrarsMap.insert((tldHash, "01"))
      val containsOp = registrarsMap.lookUp(tldHash)

      val tb = ctx.newTxBuilder()

      val registryInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()
          .convertToInputWith(fakeTxId3, fakeIndex)

      var mintResolverBox =
        tb
          .outBoxBuilder
          .value(500000000000000000L)
          .tokens(new ErgoToken(mintResolverNft, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)
      val insertLabel = resolversMap.insert((Blake2b256.hash(label ++ tld), registryInBox.getId))
      mintResolverBox = mintResolverBox.withContextVars(
        new ContextVar(0.toByte, containsOp.proof.ergoValue),
        new ContextVar(1.toByte, insertLabel.proof.ergoValue))

      val registryOutBox =
        tb
          .outBoxBuilder()
          .value(200000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()

      val mintResolverOutBox =
        tb
          .outBoxBuilder
          .tokens(new ErgoToken(mintResolverNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()

      val resolverOutBox =
        tb
          .outBoxBuilder()
          .tokens(new ErgoToken(registryInBox.getId, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), fakeScript))
          .build()

      val tx = tb
        .fee(1e7.toLong)
        .addInputs(registryInBox, mintResolverBox)
        .addOutputs(registryOutBox, mintResolverOutBox, resolverOutBox)
        .sendChangeTo(Address.create("4MQyML64GnzMxZgm"))
        .build()

      (the[InterpreterException] thrownBy prover.sign(tx)).getMessage should be("Script reduced to false")
    })
  }

  "MintResolver" should "fail if Resolver out box has wrong label" in {
    ergoClient.execute(ctx => {
      val prover = ctx.newProverBuilder()
        .withDLogSecret(secretKey.privateInput.w)
        .build()

      // coll[byte] -> byte (blake2b256(tld) -> 1)
      val registrarsMap = new PlasmaMap[Array[Byte], String](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      // coll[byte] -> ErgoId (hashed name -> nft)
      val resolversMap = new PlasmaMap[Array[Byte], ErgoId](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)

      val tld = "erg"
      val label = "helloworld"
      val resolvedToAddress = "4MQyML64GnzMxZgm"
      val tldHash = Blake2b256.hash(tld)

      val _ = registrarsMap.insert((tldHash, "01"))
      val containsOp = registrarsMap.lookUp(tldHash)

      val tb = ctx.newTxBuilder()

      val registryInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()
          .convertToInputWith(fakeTxId3, fakeIndex)

      var mintResolverBox =
        tb
          .outBoxBuilder
          .value(500000000000000000L)
          .tokens(new ErgoToken(mintResolverNft, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)
      val insertLabel = resolversMap.insert((Blake2b256.hash(label ++ tld), registryInBox.getId))
      mintResolverBox = mintResolverBox.withContextVars(
        new ContextVar(0.toByte, containsOp.proof.ergoValue),
        new ContextVar(1.toByte, insertLabel.proof.ergoValue))

      val registryOutBox =
        tb
          .outBoxBuilder()
          .value(200000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()

      val mintResolverOutBox =
        tb
          .outBoxBuilder
          .tokens(new ErgoToken(mintResolverNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()

      val resolverOutBox =
        tb
          .outBoxBuilder()
          .tokens(new ErgoToken(registryInBox.getId, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of("test".getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), resolverScript))
          .build()

      val tx = tb
        .fee(1e7.toLong)
        .addInputs(registryInBox, mintResolverBox)
        .addOutputs(registryOutBox, mintResolverOutBox, resolverOutBox)
        .sendChangeTo(Address.create("4MQyML64GnzMxZgm"))
        .build()

      (the[InterpreterException] thrownBy prover.sign(tx)).getMessage should be("Script reduced to false")
    })
  }

  "MintResolver" should "fail if Resolver out box has wrong tld" in {
    ergoClient.execute(ctx => {
      val prover = ctx.newProverBuilder()
        .withDLogSecret(secretKey.privateInput.w)
        .build()

      // coll[byte] -> byte (blake2b256(tld) -> 1)
      val registrarsMap = new PlasmaMap[Array[Byte], String](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      // coll[byte] -> ErgoId (hashed name -> nft)
      val resolversMap = new PlasmaMap[Array[Byte], ErgoId](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)

      val tld = "erg"
      val label = "helloworld"
      val resolvedToAddress = "4MQyML64GnzMxZgm"
      val tldHash = Blake2b256.hash(tld)

      val _ = registrarsMap.insert((tldHash, "01"))
      val containsOp = registrarsMap.lookUp(tldHash)

      val tb = ctx.newTxBuilder()

      val registryInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()
          .convertToInputWith(fakeTxId3, fakeIndex)

      var mintResolverBox =
        tb
          .outBoxBuilder
          .value(500000000000000000L)
          .tokens(new ErgoToken(mintResolverNft, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)
      val insertLabel = resolversMap.insert((Blake2b256.hash(label ++ tld), registryInBox.getId))
      mintResolverBox = mintResolverBox.withContextVars(
        new ContextVar(0.toByte, containsOp.proof.ergoValue),
        new ContextVar(1.toByte, insertLabel.proof.ergoValue))

      val registryOutBox =
        tb
          .outBoxBuilder()
          .value(200000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()

      val mintResolverOutBox =
        tb
          .outBoxBuilder
          .tokens(new ErgoToken(mintResolverNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()

      val resolverOutBox =
        tb
          .outBoxBuilder()
          .tokens(new ErgoToken(registryInBox.getId, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of("noa".getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), resolverScript))
          .build()

      val tx = tb
        .fee(1e7.toLong)
        .addInputs(registryInBox, mintResolverBox)
        .addOutputs(registryOutBox, mintResolverOutBox, resolverOutBox)
        .sendChangeTo(Address.create("4MQyML64GnzMxZgm"))
        .build()

      (the[InterpreterException] thrownBy prover.sign(tx)).getMessage should be("Script reduced to false")
    })
  }

  "MintResolver" should "fail if Resolver out box has wrong address" in {
    ergoClient.execute(ctx => {
      val prover = ctx.newProverBuilder()
        .withDLogSecret(secretKey.privateInput.w)
        .build()

      // coll[byte] -> byte (blake2b256(tld) -> 1)
      val registrarsMap = new PlasmaMap[Array[Byte], String](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      // coll[byte] -> ErgoId (hashed name -> nft)
      val resolversMap = new PlasmaMap[Array[Byte], ErgoId](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)

      val tld = "erg"
      val label = "helloworld"
      val resolvedToAddress = "4MQyML64GnzMxZgm"
      val tldHash = Blake2b256.hash(tld)

      val _ = registrarsMap.insert((tldHash, "01"))
      val containsOp = registrarsMap.lookUp(tldHash)

      val tb = ctx.newTxBuilder()

      val registryInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()
          .convertToInputWith(fakeTxId3, fakeIndex)

      var mintResolverBox =
        tb
          .outBoxBuilder
          .value(500000000000000000L)
          .tokens(new ErgoToken(mintResolverNft, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)
      val insertLabel = resolversMap.insert((Blake2b256.hash(label ++ tld), registryInBox.getId))
      mintResolverBox = mintResolverBox.withContextVars(
        new ContextVar(0.toByte, containsOp.proof.ergoValue),
        new ContextVar(1.toByte, insertLabel.proof.ergoValue))

      val registryOutBox =
        tb
          .outBoxBuilder()
          .value(200000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()

      val mintResolverOutBox =
        tb
          .outBoxBuilder
          .tokens(new ErgoToken(mintResolverNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()

      val resolverOutBox =
        tb
          .outBoxBuilder()
          .tokens(new ErgoToken(registryInBox.getId, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of("testaddress".getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), resolverScript))
          .build()

      val tx = tb
        .fee(1e7.toLong)
        .addInputs(registryInBox, mintResolverBox)
        .addOutputs(registryOutBox, mintResolverOutBox, resolverOutBox)
        .sendChangeTo(Address.create("4MQyML64GnzMxZgm"))
        .build()

      (the[InterpreterException] thrownBy prover.sign(tx)).getMessage should be("Script reduced to false")
    })
  }

  "MintResolver" should "fail if Resolver out box has no nft" in {
    ergoClient.execute(ctx => {
      val prover = ctx.newProverBuilder()
        .withDLogSecret(secretKey.privateInput.w)
        .build()

      // coll[byte] -> byte (blake2b256(tld) -> 1)
      val registrarsMap = new PlasmaMap[Array[Byte], String](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      // coll[byte] -> ErgoId (hashed name -> nft)
      val resolversMap = new PlasmaMap[Array[Byte], ErgoId](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)

      val tld = "erg"
      val label = "helloworld"
      val resolvedToAddress = "4MQyML64GnzMxZgm"
      val tldHash = Blake2b256.hash(tld)

      val _ = registrarsMap.insert((tldHash, "01"))
      val containsOp = registrarsMap.lookUp(tldHash)

      val tb = ctx.newTxBuilder()

      val registryInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()
          .convertToInputWith(fakeTxId3, fakeIndex)

      var mintResolverBox =
        tb
          .outBoxBuilder
          .value(500000000000000000L)
          .tokens(new ErgoToken(mintResolverNft, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)
      val insertLabel = resolversMap.insert((Blake2b256.hash(label ++ tld), registryInBox.getId))
      mintResolverBox = mintResolverBox.withContextVars(
        new ContextVar(0.toByte, containsOp.proof.ergoValue),
        new ContextVar(1.toByte, insertLabel.proof.ergoValue))

      val registryOutBox =
        tb
          .outBoxBuilder()
          .value(200000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()

      val mintResolverOutBox =
        tb
          .outBoxBuilder
          .tokens(new ErgoToken(mintResolverNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()

      val resolverOutBox =
        tb
          .outBoxBuilder()
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), resolverScript))
          .build()

      val tx = tb
        .fee(1e7.toLong)
        .addInputs(registryInBox, mintResolverBox)
        .addOutputs(registryOutBox, mintResolverOutBox, resolverOutBox)
        .sendChangeTo(Address.create("4MQyML64GnzMxZgm"))
        .build()

      // attempted to index resolverOutBox.tokens(0)
      an[ArrayIndexOutOfBoundsException] should be thrownBy prover.sign(tx)
    })
  }

  "MintResolver" should "fail if successor box script isn't preserved" in {
    ergoClient.execute(ctx => {
      val prover = ctx.newProverBuilder()
        .withDLogSecret(secretKey.privateInput.w)
        .build()

      // coll[byte] -> byte (blake2b256(tld) -> 1)
      val registrarsMap = new PlasmaMap[Array[Byte], String](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      // coll[byte] -> ErgoId (hashed name -> nft)
      val resolversMap = new PlasmaMap[Array[Byte], ErgoId](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)

      val tld = "erg"
      val label = "helloworld"
      val resolvedToAddress = "4MQyML64GnzMxZgm"
      val tldHash = Blake2b256.hash(tld)

      val _ = registrarsMap.insert((tldHash, "01"))
      val containsOp = registrarsMap.lookUp(tldHash)

      val tb = ctx.newTxBuilder()

      val registryInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()
          .convertToInputWith(fakeTxId3, fakeIndex)

      var mintResolverBox =
        tb
          .outBoxBuilder
          .value(500000000000000000L)
          .tokens(new ErgoToken(mintResolverNft, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)
      val insertLabel = resolversMap.insert((Blake2b256.hash(label ++ tld), registryInBox.getId))
      mintResolverBox = mintResolverBox.withContextVars(
        new ContextVar(0.toByte, containsOp.proof.ergoValue),
        new ContextVar(1.toByte, insertLabel.proof.ergoValue))

      val registryOutBox =
        tb
          .outBoxBuilder()
          .value(200000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()

      val mintResolverOutBox =
        tb
          .outBoxBuilder
          .tokens(new ErgoToken(mintResolverNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()

      val resolverOutBox =
        tb
          .outBoxBuilder()
          .tokens(new ErgoToken(registryInBox.getId, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), resolverScript))
          .build()

      val tx = tb
        .fee(1e7.toLong)
        .addInputs(registryInBox, mintResolverBox)
        .addOutputs(registryOutBox, mintResolverOutBox, resolverOutBox)
        .sendChangeTo(Address.create("4MQyML64GnzMxZgm"))
        .build()

      (the[InterpreterException] thrownBy prover.sign(tx)).getMessage should be("Script reduced to false")
    })
  }

  "MintResolver" should "fail if successor box tokens aren't preserved" in {
    ergoClient.execute(ctx => {
      val prover = ctx.newProverBuilder()
        .withDLogSecret(secretKey.privateInput.w)
        .build()

      // coll[byte] -> byte (blake2b256(tld) -> 1)
      val registrarsMap = new PlasmaMap[Array[Byte], String](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      // coll[byte] -> ErgoId (hashed name -> nft)
      val resolversMap = new PlasmaMap[Array[Byte], ErgoId](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)

      val tld = "erg"
      val label = "helloworld"
      val resolvedToAddress = "4MQyML64GnzMxZgm"
      val tldHash = Blake2b256.hash(tld)

      val _ = registrarsMap.insert((tldHash, "01"))
      val containsOp = registrarsMap.lookUp(tldHash)

      val tb = ctx.newTxBuilder()

      val registryInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()
          .convertToInputWith(fakeTxId3, fakeIndex)

      var mintResolverBox =
        tb
          .outBoxBuilder
          .value(500000000000000000L)
          .tokens(new ErgoToken(mintResolverNft, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)
      val insertLabel = resolversMap.insert((Blake2b256.hash(label ++ tld), registryInBox.getId))
      mintResolverBox = mintResolverBox.withContextVars(
        new ContextVar(0.toByte, containsOp.proof.ergoValue),
        new ContextVar(1.toByte, insertLabel.proof.ergoValue))

      val registryOutBox =
        tb
          .outBoxBuilder()
          .tokens(new ErgoToken(mintResolverNft, 1))
          .value(200000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()

      val mintResolverOutBox =
        tb
          .outBoxBuilder
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()

      val resolverOutBox =
        tb
          .outBoxBuilder()
          .tokens(new ErgoToken(registryInBox.getId, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), resolverScript))
          .build()

      val tx = tb
        .fee(1e7.toLong)
        .addInputs(registryInBox, mintResolverBox)
        .addOutputs(registryOutBox, mintResolverOutBox, resolverOutBox)
        .sendChangeTo(Address.create("4MQyML64GnzMxZgm"))
        .build()

      (the[InterpreterException] thrownBy prover.sign(tx)).getMessage should be("Script reduced to false")
    })
  }

  "MintResolver" should "fail if Resolver out box wouldn't be spendable based on secrets used to sign the tx" in {
    ergoClient.execute(ctx => {
      val prover = ctx.newProverBuilder()
        .withDLogSecret(BigInt.apply(0).bigInteger)
        .build()

      // coll[byte] -> byte (blake2b256(tld) -> 1)
      val registrarsMap = new PlasmaMap[Array[Byte], String](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      // coll[byte] -> ErgoId (hashed name -> nft)
      val resolversMap = new PlasmaMap[Array[Byte], ErgoId](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)

      val tld = "erg"
      val label = "helloworld"
      val resolvedToAddress = "4MQyML64GnzMxZgm"
      val tldHash = Blake2b256.hash(tld)

      val _ = registrarsMap.insert((tldHash, "01"))
      val containsOp = registrarsMap.lookUp(tldHash)

      val tb = ctx.newTxBuilder()

      val registryInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()
          .convertToInputWith(fakeTxId3, fakeIndex)

      var mintResolverBox =
        tb
          .outBoxBuilder
          .value(500000000000000000L)
          .tokens(new ErgoToken(mintResolverNft, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)
      val insertLabel = resolversMap.insert((Blake2b256.hash(label ++ tld), registryInBox.getId))
      mintResolverBox = mintResolverBox.withContextVars(
        new ContextVar(0.toByte, containsOp.proof.ergoValue),
        new ContextVar(1.toByte, insertLabel.proof.ergoValue))

      val registryOutBox =
        tb
          .outBoxBuilder()
          .value(200000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()

      val mintResolverOutBox =
        tb
          .outBoxBuilder
          .tokens(new ErgoToken(mintResolverNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()

      val resolverOutBox =
        tb
          .outBoxBuilder()
          .tokens(new ErgoToken(registryInBox.getId, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), resolverScript))
          .build()

      val tx = tb
        .fee(1e7.toLong)
        .addInputs(registryInBox, mintResolverBox)
        .addOutputs(registryOutBox, mintResolverOutBox, resolverOutBox)
        .sendChangeTo(Address.create("4MQyML64GnzMxZgm"))
        .build()

      (the[AssertionError] thrownBy prover.sign(tx)).getMessage should include("Tree root should be real but was UnprovenSchnorr")
    })
  }

  "MintResolver" should "mint a new Resolver box" in {
    ergoClient.execute(ctx => {
      val prover = ctx.newProverBuilder()
        .withDLogSecret(secretKey.privateInput.w)
        .build()

      // coll[byte] -> byte (blake2b256(tld) -> 1)
      val registrarsMap = new PlasmaMap[Array[Byte], String](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)
      // coll[byte] -> ErgoId (hashed name -> nft)
      val resolversMap = new PlasmaMap[Array[Byte], ErgoId](AvlTreeFlags.AllOperationsAllowed, PlasmaParameters.default)

      val tld = "erg"
      val label = "helloworld"
      val resolvedToAddress = "4MQyML64GnzMxZgm"
      val tldHash = Blake2b256.hash(tld)

      val _ = registrarsMap.insert((tldHash, "01"))
      val containsOp = registrarsMap.lookUp(tldHash)

      val tb = ctx.newTxBuilder()

      val registryInBox =
        tb
          .outBoxBuilder
          .value(100000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()
          .convertToInputWith(fakeTxId3, fakeIndex)

      var mintResolverBox =
        tb
          .outBoxBuilder
          .value(500000000000000000L)
          .tokens(new ErgoToken(mintResolverNft, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes), ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()
          .convertToInputWith(fakeTxId2, fakeIndex)
      val insertLabel = resolversMap.insert((Blake2b256.hash(label ++ tld), registryInBox.getId))
      mintResolverBox = mintResolverBox.withContextVars(
        new ContextVar(0.toByte, containsOp.proof.ergoValue),
        new ContextVar(1.toByte, insertLabel.proof.ergoValue))

      val registryOutBox =
        tb
          .outBoxBuilder()
          .value(200000000000000000L)
          .registers(registrarsMap.ergoValue, resolversMap.ergoValue)
          .contract(ctx.compileContract(ConstantsBuilder.empty(), registryScript))
          .build()

      val mintResolverOutBox =
        tb
          .outBoxBuilder
          .tokens(new ErgoToken(mintResolverNft, 1))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), mintResolverScript))
          .build()

      val resolverOutBox =
        tb
          .outBoxBuilder()
          .tokens(new ErgoToken(registryInBox.getId, 1))
          .registers(ErgoValue.of(pkGe), ErgoValue.of(label.getBytes), ErgoValue.of(tld.getBytes),  ErgoValue.of(resolvedToAddress.getBytes))
          .contract(ctx.compileContract(ConstantsBuilder.empty(), resolverScript))
          .build()

      val tx = tb
        .fee(1e7.toLong)
        .addInputs(registryInBox, mintResolverBox)
        .addOutputs(registryOutBox, mintResolverOutBox, resolverOutBox)
        .sendChangeTo(Address.create("4MQyML64GnzMxZgm"))
        .build()

      noException should be thrownBy prover.sign(tx)
    })
  }
}