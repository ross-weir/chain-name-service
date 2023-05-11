package cns

object Constants {
  // Registry action nfts
  val newRegistrarNft = "e66257a0f046789ecb95893f56a16e4446880b874b763d1f8cdc287abecc6c58"
  val mintResolverNft = "ba57c53a215c8d135ff067e3e7b3a11da64690041a20f659e3a1cc14b1c7ae37"
  val registryAdminNft = "94af8793a1f7b427831dcb48368ffc55c68d319d525ea24510ac38b75e280a8c"

  val nftDictionary: Map[String, String] = Map(
    "newRegistrarNft" -> newRegistrarNft,
    "mintResolverNft" -> mintResolverNft,
    "registryAdminNft" -> registryAdminNft
  )

  def substitute(contract: String): String = {
    nftDictionary.foldLeft(contract) { case (c, (k, v)) =>
      c.replace("$" + k, v)
    }
  }

  def readContract(path: String) = {
    substitute(scala.io.Source.fromFile("contracts/" + path, "utf-8").getLines.mkString("\n"))
  }

  val registryScript = readContract("Registry/Registry.es")

  val newRegistrarScript = readContract("Registry/NewRegistrar.es")

  val mintResolverScript = readContract("Registry/MintResolver.es")
}
