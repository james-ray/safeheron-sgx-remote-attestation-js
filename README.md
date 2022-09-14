# safeheron-sgx-remote-attestation-js

![img](doc/logo.png)

**safeheron-sgx-remote-attestation-js** is a demo to give a verification of TEE report from the result generated by [sgx-arweave-cpp](https://github.com/Safeheron/sgx-arweave-cpp) after checking if the MRENCLAVE of your deployed service is identical to [current MRENCLAVE](https://github.com/Safeheron/sgx-arweave-cpp/blob/main/doc/MRENCLAVE_TABLE.md).


# Build & Run

```shell
$ npm install 
$ npm run build 
$ npm run test
```
# Usage

## Input File
[data.json](https://github.com/Safeheron/safeheron-sgx-remote-attestation-js/blob/main/data/data.json) is the input file that contains:
* `tee_return_data` the callback return data from [sgx-arweave-cpp](https://github.com/Safeheron/sgx-arweave-cpp);
* `private_key_list` the private key list that contains users' private key corresponding to the public keys in [user_public_key_list](https://github.com/Safeheron/sgx-arweave-cpp/tree/main#generation-request-details). You can fill into this list with private keys according to your generation request.


The example is below:
```json
{
  "tee_return_data" : {
    "pubkey_list_hash":	"f6fca699eae08f95900e06744487f421a9e516c896efb72af4a7aad375c30636",
    "key_shard_pkg":	[{
      "public_key":	"0424c0853bdcb04fb8d50eaaa779f2c0d5f01c79b30b58f6a2fe739070e236cd142e32b8114f06b60b46b00f39745c874e8297ec9da01366927ac199072a103356",
      "encrypt_key_info":	"0484a34017f0a00bdd4fd5fab9609c93e8af69a66cd21dd62e8e9b583d74cce54e50e5ca6146dcffaf8a4d0af5a85e397a99bae5984e3044ab93d75c68f834ba3023a748bb48b34e6103916c4a2d0a9249e9902b6ea54deba54914fefec0f44c24b5cf201426d4f012c412ff3abd5af4ed046077915d8030e75259f93d11a1f3c003a36a0a29551458af0b30622b85a2a99649ae350aac0362d1c732afddb9a1a5bfb1352b785421732573bdd7289877dec6c58b347871ec04c3900295a360086e83088830c418f997232e2c6d3a842938c0f6b084aff354700af050f3e55c72071029901d4de621178cace30a26530b9f0526d302475f7a2c937d151c8792ec92e0827c98d1e635cf8de88303c82d0004ad1c4e454a21fb596e8d8dae2f9a7fb0ce0afdcb754132ca52b8b49b32d431a3c2ab4323ceaa875cfbac6b412f531226124e4b936e4a254aa1cf60362d50eb6cf2fc252fb570d6215017fdda7168fe38cc3bb70da73fb3a43bd27526572a35fd993a4003d5aa711aa6adb533133bb1cedc7176a198ad1afa1cbae1aab025df8cd80acd27a67321ab72467bc7171399655bddab2de8587467663e166e2b5f2a37361a6eb0fe074aab5b4f6b267c8e3d61e225e193d398fa69d290e7f72b7c91c139e418cc3ab3a22578025c4b9f483cd1fb5bb6fee81f0bde99e1aba501e24b2555c730999ee1e27e8b37d8ac337ff29e7ae77fd432b5abacf2633da17cc18c8b0fdb46a55b10be1a92353d5b8064e96650b93666c1b7dafab2e4649501082208cb6c95a13f0fdee810c8144a1eb18f3ea0f8fce51f0e8ac2c80dd5ba98bc20a6dd6517d2df176494d89517d265fa46a03c928b3ae6ba8bf9a42489780e224192ac88f7eb9fb908c65103e733c572eb6371a9f8197ef1eb8bf4054cb2c92f6c24724f8840d1835e239ded0a0ab3e505d25d102a9e9066d205c032f6180003d70540b5fa0931d24993b6c1bb32436fd9c622d1944bb73bd34dd8a3220ec5de5448db15aeb96d459769b995fa789687a0e78ce46623130460e503948879c6524fa12da714b4cdff266453af9ac8a071c217d61f810c0bffa899725a8bf864ab9c3d7ccd3ff67c270a08f5a778c38f4a46414aca3bb011741fbf0cdac4d0160aacb3c174c136eca1ce66d2dcab0deb22e4eca7c8122d698b7b6a8023e704110974727c319d7d73d8de5f21f6c5705e626a6672681ca64f23776ad30d5526996087dd46187b7e4168e389b3a37d6b53cd941e95e52311cf89629c0df07453e3691d3b369f38ea3ab35e64a549477bd6558bcd9af86b23aad21b1fdf758560bf3144d4a794edde48e62f2d2271db645edb3ecf2b0064d9ae9ba5742e82ba79b27aacb4549d69b9bf254ee52dc47a7ccee85b03c6425e7ef8a2008033093c931b7a4ab9b6ee20c1a4b2da0b365cf67d66effe42ff510590af1025140095f042016d4ac391265975fa94912daa10940495b514b7cc49ef4d74e7cd10064ffcbe3a60c1f214f94679aa1e8c041d165271f160e33ee125e77bf6046d565ae868773f6d900c814285d6f06a201027bd4ba4cc308c560d7400af3b06e21889e536488a65a5cdbce044a89b7e906261082e554cb5d4bf4e3a77e0f3555777ac14ec5174cbb1b2"
    }, {
      "public_key":	"049f992995affb335b576a7186316fc0ecfcca3d88f78dfb00e0e76e1f9a9766135230831442e4b1975f2caf81756a250032ea5e165ba1631606795be04a00d42c",
      "encrypt_key_info":	"044bcdf6d33193a46d46b802536540839f39b8e86464c995d03458459cbf0aa96438790d21c86cd02a7e3ec1a2d1330900dea3876496764fe4cdb86c11e21bf382fc95c36a6424a251f5decfa39bfe0d51d5ebb2ea919fcd935495cebaa605f946cc9de96d4189b66a58e01d74459bf4777be5ce8f9835ddd6e1cc011c768036e86ab75e6f105e5ac035ebd886313a15cfc2620539848a2cedf5433bb59fb67fc2f08e241f11bc3d99e9f426c4eefc49bc8366912a17c09659002aaa7ec9780ce6585c25ec67ae11639174c99a641314c234ee90f3aaf9d35cf7a816907d2cbf5161dfe71822297b1de0c8b4d173e8d90d67d5c0b7fba8eed62338046a888343f1cf8e5c5e4263c2966f663dded8b2908513427d40acf2e816a00adae6ef7a717bdde98292c510322d9fbf6d154fd62792fddad20b31a5a4bfb70f794d71146bc23f286918d5990d3f819c05920fcb3cc48b8f60cc6f240f4c1cb18422400772bb5265d19aff369784bdc81c484f2e8f453143c707d81ea592183e15c22b7e391d27b9e4216ce74643b481e861086bbfa77060ce0d83757c32ad234708b19af6c131ebe2fa6039c445854e3b3598812b16af72c77e00846d57345a6e810eff1c98627efadcf192fbaff30a41e7044130f4a3373a54c9e47ac97a32d9ad670b5a3f770081896a0cad008a44fe946d7b45cdb465f4a2097c80ccdfb3083204cb994ba7b2df2defb70327d7aa26a64288b43eb2473a8b257affb97edaf41cf42c25556b1d6f0f45ed80f23bcc9b7a97fad87532e0038ea318f0a971436359eb700c7541312b641e04b4fc173ebe63659ec5950a4a44028dbc6063c128ef439d9e01dada7f354f0b5297363e7f36c3d8da8a2e514d99c56db3d0dccc034e838584b56a564ff8f67ee57ee090325a17122791d70772cebcdbfa493963855a69cc4c576704b1ff4a081798e9f3f09c315bb0da296d9945305f9760ef325fd35637c5705dd87e39e88f1af3621516f79ff0b1ef22de8204779bee0989ae8c45634d919cccfe9168ed096e2adbed3c54bb8d66a6337b3ea2e91ee6781e0b827b4e1f07799dca21b5f15d5843a7e4736d5ff0fb831ad79c9a2e230f5b04013f9ce2db8b63e56ce89966db2c8f1a0b3cda43294645ba177be85456cb91441a738cfb8f321f43e06c59861ae00f56efe5ec22106385e0839a166b77b56c9bbd019f2691da585b9891d40ba4a8dfa2b9e907c6d23ba12f45e9c27e071093243d381e5582269dd207403a2ba630c4bd641bc4be83cab49977bde5038472d04f64bb83112cba7fe5473826cddd1345bcddb896780e5bc5af756cbacfa67279d2bad3d2926b3c7eaaf006e1415f5dc42bd19cbd87d9523fc863ed1ac9963d99df485145d5b18bb41f2e25e48c62827396df20602c3fc685dd7f801f609c1c1fef235bbc769c517058b55669a4caecfef695451600404e2f6d3f12f5cca12f2f11a349e2cce70c637c2718fa7cc86e3442173ef93b03a740bf33ae275764750690bb7599a69d2b8f2a0b5e13e0085843d31dc12898b3e7fe1a51754ecf51ba9e4ccbd545620f573fe17d38eece95ad1ffafaf0e1b8dbf06a18266c9a0b337379c258437440ff05f24cb84a04c2d39e3f9860b35026822f07bb"
    }, {
      "public_key":	"04e30cd9f1283b95251e2721ee6f1fcbbc6ea56f32c924c0000f6f4e6a91d474dd1ff40d39fb8601b4b4066027952ede10e2d144f1b3aa5b2b1bf4210f4cc93e3d",
      "encrypt_key_info":	"0493dc0b26cecf7864123ef04925e83760bbba9d12cc1ba16e0315c71bbd78e6d2d047fb9bf53ea4fca3761e5fe691e508e6ed5b95953f7a2cb5737dae2a40f25bf7948e21f323db58a7f28cb87a6a0c1204ee2a02f6d29ff727c6a91d575e1867a13a3d5458141b519c22fbe3d4562a00d6934a786a5cd0635e1e41f909cf2de1e1683381125ce78faaaea46d994207cb26f33f048e7ccd2a35f49caeca9eb445b52120e1ccd9b3fdeaa81fc4ce3ccce558bd24964085fd3e36fece02d7e5ed77d1f0f6eb298e782e1d7524aca10416e163c9baf290b0552815fa3a12772472f9d4e6d057d314f9bfa7092d7a9e3bc3627de49398c3880d04be8ffd39397f479addcac37ade750a1cf6b09c685cedfc4aed78ecdb3e32ee6deacd395c528c54ac7b3a1130a013a9b77b433c1f7c5b4f4c9895f03ca743b810182fb2a914147bb5f20272ceaec84ce98a43df67113c8c7a22f82927279ca24dcd3a9d91cd0858640486e263e4997020a594c59690c04b1106559be596f8c2e1bdf32aab07900edb5cfad4cbb2b698ecc9faf05fa6e66bf894368a6dcf740c9aa3c6340fd5c9fd6ddcb60a7264e5b285ff3a978b3435b72ac7e0d54dda4a18281d65804df530c853a820213b818aec3f591e1e5e5b699d661d18548d2a88a5cafa06c2c4d92355ce0e0833260358db2c81c172215aa3800df7709f4a8cb06a31e59faef0e2de935bfd9b30b739e6f0273b3cfe0eaccb41a9c814ca772cd5f6d17a14eaba3b3f669de15a2f0cbedf7ab3f514525261d0a3993697c0b8bfe4ca5642fb242ac6d3d619496b26d434d2346cd8460c6e1636a9f3fbbbc8c119ad913c9dfe7931d71ede046fb50a947cd0b973ceccc9c8504565b29b52d39ca73776d43c0ab20ac3ac94996cb14e909209c8d6c2de43b4d96f616d3f80a557a21faff252e5fb2a200aacae56d3e3936a6c360f7ec456bd2df531b51e63266ccf9700ad487736ca267577b88c76e463a6ea3b524fc73c67534fe4af4673673273ad86e3afea34b8dfc09ce6e07dfb2ef936ef0e628818fe761301079aef7430e089b202c3003f57626a93963a82c26b42bbd75ac3597a5aa5ce7c265da1bc0eae29bedbcaf966468765ee2f1e22242288c514258f9ad08562989df0c5746da6bbe7252597cff052aec67c3da6513bb78332796730fae4818e8dc4514ef0a74abd9412477c55be828e22967aff5ea475aaca114904de601e48d32f4eeb7940bd4c0b35c36e68a1840af1ef1a61ce268b85f84a7ef238f9d0153b46d57b38daf95b5a32ec8e170080b738beaef0aa29acb4d0ac9c191b0721b3411695ce4d16acb6a2f4a8587c84232a303f16852439646f47a72bc6de8c7d1fb0bf09fe581008d2970d6305aaffad3708eeecb84b2c10ec1a781b429569e5437b0f825196525de285f341ba9345308fe4ce441a25b60cbabadd1a631eeab7ceeb2f804bb5abecce93d7b7f12c1c503d4ecc97c33cc68724f4dd2f27da545d58afec0717f3fb07487e1a4431f58fad4cf76f41acbf388e5920083c8c6024fa816cb980941fa3f02a05586a92f7788149c120ec910e556f6789a84e747a3ad70817a957e0a2dfd49487b9b851b9d3adb9cd0f0394639aa3cd94de86f6e5da7c3919bacc"
    }],
    "tee_report":	"AwACAAAAAAAIAA0Ak5pyM/ecTKmUCg2zlX8GBy2X2CVjiLXgeJBLN9tt8MkAAAAABQUICf//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAADnAAAAAAAAACSJRJA96RepNnFEQISisaedE+ON/87tHcWQDwDbqpoEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmHTuXcuQ5HTRZ1wS7tEywKmp++n5QBpsuLerAlWzc5gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyRAAAJ/3ZW+lEo2bMB4WcQYE1NZSW3z3gs0hrQX1SMxCMnhNs3cywWCv/gWmwairuuYRqlwLge1Gh4O393C94VZWYCFWCTJNIRm3aaNV/6qNb3UAUROcpUCJAi3X2ThBPgpekDoPjFZLiXT3rw/3e71LRM2plquj0fEDeT9D/Uwa3wNZBQUICf//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFQAAAAAAAADnAAAAAAAAAIzlhoW+NuRhh8Izx+me1v5127M/dWetohewd+zYz4L5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACMT1d115ZQPpYTf3fGioKaAFasje1wFAsIGwlEkMV7/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAviobr5ifeZ36aGOOvp3ILx2nE22vO0BfITMPO8L5lpQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApv1Yxs4vojQNyZDq3ADY39ZbdbuvIMhZV0HxYSDHle9anFtzsQp/KQFdHku+L4WwJ5/ON065ualIjk/qybphKiAAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8FAGEOAAAtLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJRTh6Q0NCSm1nQXdJQkFnSVZBSnoraFR4ZzV3OFNGU0tkY2xRU3djMWg0SnBiTUFvR0NDcUdTTTQ5QkFNQwpNSEF4SWpBZ0JnTlZCQU1NR1VsdWRHVnNJRk5IV0NCUVEwc2dVR3hoZEdadmNtMGdRMEV4R2pBWUJnTlZCQW9NCkVVbHVkR1ZzSUVOdmNuQnZjbUYwYVc5dU1SUXdFZ1lEVlFRSERBdFRZVzUwWVNCRGJHRnlZVEVMTUFrR0ExVUUKQ0F3Q1EwRXhDekFKQmdOVkJBWVRBbFZUTUI0WERUSXlNRGN6TURFMU5UUTFNbG9YRFRJNU1EY3pNREUxTlRRMQpNbG93Y0RFaU1DQUdBMVVFQXd3WlNXNTBaV3dnVTBkWUlGQkRTeUJEWlhKMGFXWnBZMkYwWlRFYU1CZ0dBMVVFCkNnd1JTVzUwWld3Z1EyOXljRzl5WVhScGIyNHhGREFTQmdOVkJBY01DMU5oYm5SaElFTnNZWEpoTVFzd0NRWUQKVlFRSURBSkRRVEVMTUFrR0ExVUVCaE1DVlZNd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFSSgo3U3AvYmllL3IzNndJdXloTkNIYjh5bVl0OHZ5NllIdGJFc3NIOUl0bGZZbE5SS3Qza3QyNk10NnVnZnc3S2lVClBWeDVTTzJXTGw3MEJMVGk3Q0JQbzRJRERqQ0NBd293SHdZRFZSMGpCQmd3Rm9BVWxXOWR6YjBiNGVsQVNjblUKOURQT0FWY0wzbFF3YXdZRFZSMGZCR1F3WWpCZ29GNmdYSVphYUhSMGNITTZMeTloY0drdWRISjFjM1JsWkhObApjblpwWTJWekxtbHVkR1ZzTG1OdmJTOXpaM2d2WTJWeWRHbG1hV05oZEdsdmJpOTJNeTl3WTJ0amNtdy9ZMkU5CmNHeGhkR1p2Y20wbVpXNWpiMlJwYm1jOVpHVnlNQjBHQTFVZERnUVdCQlE2L1N5VFF0QkRVVHV0NjdRc2NMTFQKNmpJRC96QU9CZ05WSFE4QkFmOEVCQU1DQnNBd0RBWURWUjBUQVFIL0JBSXdBRENDQWpzR0NTcUdTSWI0VFFFTgpBUVNDQWl3d2dnSW9NQjRHQ2lxR1NJYjRUUUVOQVFFRUVPZ1paN3dqVmJheW9pcjJqU0VjbzFFd2dnRmxCZ29xCmhraUcrRTBCRFFFQ01JSUJWVEFRQmdzcWhraUcrRTBCRFFFQ0FRSUJCREFRQmdzcWhraUcrRTBCRFFFQ0FnSUIKQkRBUUJnc3Foa2lHK0UwQkRRRUNBd0lCQXpBUUJnc3Foa2lHK0UwQkRRRUNCQUlCQXpBUkJnc3Foa2lHK0UwQgpEUUVDQlFJQ0FQOHdFUVlMS29aSWh2aE5BUTBCQWdZQ0FnRC9NQkFHQ3lxR1NJYjRUUUVOQVFJSEFnRUFNQkFHCkN5cUdTSWI0VFFFTkFRSUlBZ0VBTUJBR0N5cUdTSWI0VFFFTkFRSUpBZ0VBTUJBR0N5cUdTSWI0VFFFTkFRSUsKQWdFQU1CQUdDeXFHU0liNFRRRU5BUUlMQWdFQU1CQUdDeXFHU0liNFRRRU5BUUlNQWdFQU1CQUdDeXFHU0liNApUUUVOQVFJTkFnRUFNQkFHQ3lxR1NJYjRUUUVOQVFJT0FnRUFNQkFHQ3lxR1NJYjRUUUVOQVFJUEFnRUFNQkFHCkN5cUdTSWI0VFFFTkFRSVFBZ0VBTUJBR0N5cUdTSWI0VFFFTkFRSVJBZ0VMTUI4R0N5cUdTSWI0VFFFTkFRSVMKQkJBRUJBTUQvLzhBQUFBQUFBQUFBQUFBTUJBR0NpcUdTSWI0VFFFTkFRTUVBZ0FBTUJRR0NpcUdTSWI0VFFFTgpBUVFFQmdCZ2FnQUFBREFQQmdvcWhraUcrRTBCRFFFRkNnRUJNQjRHQ2lxR1NJYjRUUUVOQVFZRUVCbTlBSmpiCjNack9VTlVkclZQYWFtVXdSQVlLS29aSWh2aE5BUTBCQnpBMk1CQUdDeXFHU0liNFRRRU5BUWNCQVFIL01CQUcKQ3lxR1NJYjRUUUVOQVFjQ0FRSC9NQkFHQ3lxR1NJYjRUUUVOQVFjREFRSC9NQW9HQ0NxR1NNNDlCQU1DQTBnQQpNRVVDSUdtVk9zYmJKYUh4N3dVTnZRNFZLOUJTWE5Na3N3QTA5SWpITGs5WTVSRWdBaUVBdXUydklqQ2hHeDhFCjlXWmVWVTJ4eFNHSUxhZ1VrL2d3aEFTS0VqTVNGM1k9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNsakNDQWoyZ0F3SUJBZ0lWQUpWdlhjMjlHK0hwUUVuSjFQUXp6Z0ZYQzk1VU1Bb0dDQ3FHU000OUJBTUMKTUdneEdqQVlCZ05WQkFNTUVVbHVkR1ZzSUZOSFdDQlNiMjkwSUVOQk1Sb3dHQVlEVlFRS0RCRkpiblJsYkNCRApiM0p3YjNKaGRHbHZiakVVTUJJR0ExVUVCd3dMVTJGdWRHRWdRMnhoY21FeEN6QUpCZ05WQkFnTUFrTkJNUXN3CkNRWURWUVFHRXdKVlV6QWVGdzB4T0RBMU1qRXhNRFV3TVRCYUZ3MHpNekExTWpFeE1EVXdNVEJhTUhBeElqQWcKQmdOVkJBTU1HVWx1ZEdWc0lGTkhXQ0JRUTBzZ1VHeGhkR1p2Y20wZ1EwRXhHakFZQmdOVkJBb01FVWx1ZEdWcwpJRU52Y25CdmNtRjBhVzl1TVJRd0VnWURWUVFIREF0VFlXNTBZU0JEYkdGeVlURUxNQWtHQTFVRUNBd0NRMEV4CkN6QUpCZ05WQkFZVEFsVlRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVOU0IvN3QyMWxYU08KMkN1enB4dzc0ZUpCNzJFeURHZ1c1clhDdHgydFZUTHE2aEtrNnorVWlSWkNucVI3cHNPdmdxRmVTeGxtVGxKbAplVG1pMldZejNxT0J1ekNCdURBZkJnTlZIU01FR0RBV2dCUWlaUXpXV3AwMGlmT0R0SlZTdjFBYk9TY0dyREJTCkJnTlZIUjhFU3pCSk1FZWdSYUJEaGtGb2RIUndjem92TDJObGNuUnBabWxqWVhSbGN5NTBjblZ6ZEdWa2MyVnkKZG1salpYTXVhVzUwWld3dVkyOXRMMGx1ZEdWc1UwZFlVbTl2ZEVOQkxtUmxjakFkQmdOVkhRNEVGZ1FVbFc5ZAp6YjBiNGVsQVNjblU5RFBPQVZjTDNsUXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01CSUdBMVVkRXdFQi93UUlNQVlCCkFmOENBUUF3Q2dZSUtvWkl6ajBFQXdJRFJ3QXdSQUlnWHNWa2kwdytpNlZZR1czVUYvMjJ1YVhlMFlKRGoxVWUKbkErVGpEMWFpNWNDSUNZYjFTQW1ENXhrZlRWcHZvNFVveWlTWXhyRFdMbVVSNENJOU5LeWZQTisKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQotLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJQ2p6Q0NBalNnQXdJQkFnSVVJbVVNMWxxZE5JbnpnN1NWVXI5UUd6a25CcXd3Q2dZSUtvWkl6ajBFQXdJdwphREVhTUJnR0ExVUVBd3dSU1c1MFpXd2dVMGRZSUZKdmIzUWdRMEV4R2pBWUJnTlZCQW9NRVVsdWRHVnNJRU52CmNuQnZjbUYwYVc5dU1SUXdFZ1lEVlFRSERBdFRZVzUwWVNCRGJHRnlZVEVMTUFrR0ExVUVDQXdDUTBFeEN6QUoKQmdOVkJBWVRBbFZUTUI0WERURTRNRFV5TVRFd05EVXhNRm9YRFRRNU1USXpNVEl6TlRrMU9Wb3dhREVhTUJnRwpBMVVFQXd3UlNXNTBaV3dnVTBkWUlGSnZiM1FnUTBFeEdqQVlCZ05WQkFvTUVVbHVkR1ZzSUVOdmNuQnZjbUYwCmFXOXVNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0dBMVVFQ0F3Q1EwRXhDekFKQmdOVkJBWVQKQWxWVE1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUM2bkV3TURJWVpPai9pUFdzQ3phRUtpNwoxT2lPU0xSRmhXR2pibkJWSmZWbmtZNHUzSWprRFlZTDBNeE80bXFzeVlqbEJhbFRWWXhGUDJzSkJLNXpsS09CCnV6Q0J1REFmQmdOVkhTTUVHREFXZ0JRaVpReldXcDAwaWZPRHRKVlN2MUFiT1NjR3JEQlNCZ05WSFI4RVN6QkoKTUVlZ1JhQkRoa0ZvZEhSd2N6b3ZMMk5sY25ScFptbGpZWFJsY3k1MGNuVnpkR1ZrYzJWeWRtbGpaWE11YVc1MApaV3d1WTI5dEwwbHVkR1ZzVTBkWVVtOXZkRU5CTG1SbGNqQWRCZ05WSFE0RUZnUVVJbVVNMWxxZE5JbnpnN1NWClVyOVFHemtuQnF3d0RnWURWUjBQQVFIL0JBUURBZ0VHTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFFd0NnWUkKS29aSXpqMEVBd0lEU1FBd1JnSWhBT1cvNVFrUitTOUNpU0RjTm9vd0x1UFJMc1dHZi9ZaTdHU1g5NEJnd1R3ZwpBaUVBNEowbHJIb01zK1hvNW8vc1g2TzlRV3hIUkF2WlVHT2RSUTdjdnFSWGFxST0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
  },
  "private_key_list" : ["8bab3e786c5e1ffd30dc475f62f3a5cb1aa0c5efe8ba2019e528c77ac2ba99bc", "a37359cf38aab6208599416a74e5fef293cbc3cb5e03a038e3ef37eb65ad1289", "2207e9e61ac486f2c01cfd926fe3f24252b36a68d40ce6bfdf3c5f2e5b72b7e8"]
}
```

# Content of Verification

![img](doc/Remote%20Attestation%20Report.png)

As shown in the figure above, the contents needed to be verified are:
* The `report data` from App report and QE report;
* `Quote Signature`;
* `QE Report Signature`;
* The cert chain in `Certification Data`, the cert chain is made up by **PCK Cert**, **Processor Cert** and **SGX Root Cert**;


# Process of Verification

1. Verify if the value of public key list hash is valid and calculate the **User Data**;

2. Verify if the **cert chain** from `Certification Data` is valid:

- **PCK Cert**: Verify the issuer of PCK Cert, the signature and whether it has been revoked;
- **Processor Cert**: Verify the issuer of Processor Cert, the signature and whether it has been revoked;
- **SGX Root Cert**: Verify the issuer of SGX Root Cert, the signature and whether it has been revoked. [Intel_SGX_Provisioning_Certification_RootCA.pem](https://github.com/Safeheron/safeheron-sgx-remote-attestation-js/blob/main/data/Intel_SGX_Provisioning_Certification_RootCA.pem) is the SGX Root CA Certificate downloaded from [intel_sgx_root_ca](https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem). you can substitute it with your download version;

3. Verify `Quote Signature`:

- `Quote Signature` is the ECDSA signature from ECDSA Attestation Private Key signing Report Header and App Report

4. Verify `QE Report Signature`:
- `QE Report Signature` is the ECDSA signature from PCK(Provisioning Certification Key) signing QE Report.

5. Verify the `report data` from `App Report`:
- `report data` from `App Report` is data customized by user self, that is **User Data**. In this project, report data is the hash of concatenating public key list hash and key meta hash.

6. Verify the `report data` from `QE Report`:
- `report data` from `QE Report` is the hash of concatenating `Attestation Public Key` and `Auth Data`.

## Example of successful verification
```text
*************************************************************************************************************
The public key list hash from data.json: f6fca699eae08f95900e06744487f421a9e516c896efb72af4a7aad375c30636
The calculated public key list hash: f6fca699eae08f95900e06744487f421a9e516c896efb72af4a7aad375c30636
*************************************************************************************************************
1. The public key list hash has been verified successfully!

2. The cert chain has been verified successfully!

3. The App report signature has been verified successfully!

4. The QE report signature has been verified successfully!

*************************************************************************************************************
The calculated user data: a61d3b9772e4391d3459d704bbb44cb02a6a7efa7e50069b2e2deac0956cdce6
The user data from tee_report: a61d3b9772e4391d3459d704bbb44cb02a6a7efa7e50069b2e2deac0956cdce6
*************************************************************************************************************
The calculated QE report data: 2f8a86ebe627de677e9a18e3afa7720bc769c4db6bced017c84cc3cef0be65a5
The QE report data from tee_report: 2f8a86ebe627de677e9a18e3afa7720bc769c4db6bced017c84cc3cef0be65a5
*************************************************************************************************************
5. User Data has been verified successfully!

6. QE Report Data has been verified successfully!

Verify TEE Report successfully!
```

# Development Process & Contact

This library is maintained by Safeheron. Contributions are welcomed! Besides, for GitHub issues and PRs, feel free to reach out by email.






