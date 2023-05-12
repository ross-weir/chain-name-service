package cns

import org.ergoplatform.ErgoAddressEncoder
import org.ergoplatform.ErgoAddressEncoder.TestnetNetworkPrefix
import scorex.crypto.hash.{Blake2b256, Digest32}

object Constants {
  val network: ErgoAddressEncoder.NetworkPrefix = TestnetNetworkPrefix

  // Registry action nfts
  val newRegistrarNft = "e66257a0f046789ecb95893f56a16e4446880b874b763d1f8cdc287abecc6c58"
  val mintResolverNft = "ba57c53a215c8d135ff067e3e7b3a11da64690041a20f659e3a1cc14b1c7ae37"
  val registryAdminNft = "94af8793a1f7b427831dcb48368ffc55c68d319d525ea24510ac38b75e280a8c"

  val nftDictionary: Map[String, String] = Map(
    "newRegistrarNft" -> newRegistrarNft,
    "mintResolverNft" -> mintResolverNft,
    "registryAdminNft" -> registryAdminNft,
    "resolverScriptHash" -> Utils.bytesToHex(resolverScriptHash)
  )

  private def substitute(contract: String, subs: Map[String, String]): String = {
    subs.foldLeft(contract) { case (c, (k, v)) =>
      c.replace("$" + k, v)
    }
  }

  private def readContract(path: String, subs: Map[String, String]) = {
    substitute(scala.io.Source.fromFile("contracts/" + path, "utf-8").getLines.mkString("\n"), subs)
  }

  lazy val resolverScript: String = readContract("Resolver.es", Map.empty)
  private lazy val resolverScriptTree = Utils.compile(Map.empty, resolverScript, network)
  lazy val resolverScriptHash: Digest32 = Blake2b256.hash(resolverScriptTree.bytes)

  val registryScript: String = readContract("Registry/Registry.es", nftDictionary)

  val newRegistrarScript: String = readContract("Registry/NewRegistrar.es", nftDictionary)

  val mintResolverScript: String = readContract("Registry/MintResolver.es", nftDictionary)
}
