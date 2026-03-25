// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ECVRF",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "ECVRF", targets: ["ECVRF"]),
        .executable(name: "ecvrf-test", targets: ["ECVRFTest"]),
    ],
    dependencies: [
        .package(url: "https://github.com/21-DOT-DEV/swift-secp256k1", from: "0.17.0"),
        .package(url: "https://github.com/attaswift/BigInt", from: "5.3.0"),
    ],
    targets: [
        .target(
            name: "ECVRF",
            dependencies: [
                .product(name: "libsecp256k1", package: "swift-secp256k1"),
                .product(name: "BigInt", package: "BigInt"),
            ]
        ),
        .executableTarget(
            name: "ECVRFTest",
            dependencies: ["ECVRF"]
        ),
    ]
)
