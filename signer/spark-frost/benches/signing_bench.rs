use criterion::{criterion_group, criterion_main, Criterion};
use spark_frost::{
    proto::frost::*,
    signing::{sign_frost, sign_frost_serial},
};

fn setup_signing_job() -> Result<FrostSigningJob, String> {
    let proto_hex = "0a93070a2463633730386234622d656330642d346366392d623032362d636237656133333963383461122088e3bc226daeecebe55835af5a10acd8bb2e6ac003ad06ed657c8d4c7b8e19be1af0010a40303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303036331220c07efac9e895546aef1c5b2c7167b0f11135595a7591c8e0c4399fdb7b62d4281a650a4030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303633122102343c9378f603b95b3068f7a52435c89b137d353cb300b4205ca1b0abb8da84f2222102343c9378f603b95b3068f7a52435c89b137d353cb300b4205ca1b0abb8da84f22801222103a2d60b318354f4e9f3142d22ceeb860011ae009acf62a919d933fa17fe2106002a440a202ad1006d751808a767f72b5ddef9850575f2ff7da2d0b26db3cdacb91f8c1aa91220415f61ecefe2ca04c616ec4aa61349459de78d0124c0884f7d3172946351558e328a010a403030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303512460a2102ec3ac5f0766853e2cbfcddc198ee2ab3b5cd206647dd23bcc5e95ec43f5f86a2122103bd65621522d01395f863c1109baab790114793b09b6e3c311fb753e3a8ba9c6f328a010a403030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303312460a2103d8edb567a364089b794e6ab92fa4c83dd6428f53c26ba7689946fcd48d357de012210240c7cdfc4099096a71a5f4e55136722d1f8c480643007321a829f2734d1954b0328a010a403030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303412460a2103340fb5c83ecba98702cbc790ce8b22c9ac0bacc96710a713eb7f3da58b007de61221026881878bfdfd5b6e34f9f5ed9b0885aa3ef81618bd987b78908c151c5bca16a83a460a210326bb41b9443497b0d1236e85aa5670d0f39487b203416812851c5ba8efa2fa6f1221030fde962b4279eef80c42942549c07ba7220148826fd516d07ef9533e9b2c04d41001";
    let proto_bytes =
        hex::decode(proto_hex).map_err(|e| format!("Failed to decode proto hex: {e:?}"))?;
    let request = <SignFrostRequest as prost::Message>::decode(&proto_bytes[..])
        .map_err(|e| format!("Failed to decode proto: {e:?}"))?;
    let job = request.signing_jobs.first().ok_or("No signing jobs")?;
    Ok(job.clone())
}

fn setup_frost_request(count: usize) -> Result<SignFrostRequest, String> {
    let mut request = SignFrostRequest::default();
    let job = setup_signing_job()?;

    let mut signing_jobs = Vec::new();
    for _ in 0..count {
        signing_jobs.push(job.clone());
    }
    request.signing_jobs = signing_jobs;
    request.role = SigningRole::User as i32;

    println!(
        "SignFrostRequest: {}",
        hex::encode(prost::Message::encode_to_vec(&request))
    );

    println!("Number of jobs: {}", request.signing_jobs.len());
    Ok(request)
}

fn benchmark_signing_size(c: &mut Criterion, size: usize) {
    let request = setup_frost_request(size).unwrap();
    let group_name = format!("signing_{}_items", size);

    let mut group = c.benchmark_group(&group_name);

    group.bench_function("parallel", |b| b.iter(|| sign_frost(&request)));
    group.bench_function("serial", |b| b.iter(|| sign_frost_serial(&request)));
    group.finish();
}

fn compare_signing(c: &mut Criterion) {
    // Benchmark different request sizes
    benchmark_signing_size(c, 1);
    benchmark_signing_size(c, 2);
    benchmark_signing_size(c, 5);
    benchmark_signing_size(c, 10);
    benchmark_signing_size(c, 100);
    benchmark_signing_size(c, 500);
}

criterion_group!(benches, compare_signing);
criterion_main!(benches);
