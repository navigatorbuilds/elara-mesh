use criterion::{criterion_group, criterion_main, Criterion};
use elara_runtime::dag::DagIndex;

fn build_chain(n: usize) -> DagIndex {
    let mut dag = DagIndex::new();
    for i in 0..n {
        let id = format!("n{i:05}");
        let parents = if i == 0 {
            vec![]
        } else {
            vec![format!("n{:05}", i - 1)]
        };
        dag.insert(id, parents, i as f64).unwrap();
    }
    dag
}

fn build_wide(n: usize) -> DagIndex {
    let mut dag = DagIndex::new();
    dag.insert("root".into(), vec![], 0.0).unwrap();
    for i in 0..n {
        dag.insert(format!("leaf-{i}"), vec!["root".into()], (i + 1) as f64)
            .unwrap();
    }
    dag
}

fn bench_insert_10k(c: &mut Criterion) {
    c.bench_function("dag_insert_10k_chain", |b| {
        b.iter(|| build_chain(10_000));
    });
}

fn bench_tips_10k(c: &mut Criterion) {
    let dag = build_chain(10_000);
    c.bench_function("dag_tips_10k", |b| b.iter(|| dag.tips()));
}

fn bench_roots_10k(c: &mut Criterion) {
    let dag = build_chain(10_000);
    c.bench_function("dag_roots_10k", |b| b.iter(|| dag.roots()));
}

fn bench_ancestors_10k(c: &mut Criterion) {
    let dag = build_chain(10_000);
    c.bench_function("dag_ancestors_from_tip_10k", |b| {
        b.iter(|| dag.ancestors("n09999", 10_000));
    });
}

fn bench_descendants_10k(c: &mut Criterion) {
    let dag = build_chain(10_000);
    c.bench_function("dag_descendants_from_root_10k", |b| {
        b.iter(|| dag.descendants("n00000", 10_000));
    });
}

fn bench_wide_dag_tips(c: &mut Criterion) {
    let dag = build_wide(10_000);
    c.bench_function("dag_tips_10k_wide", |b| b.iter(|| dag.tips()));
}

criterion_group!(
    benches,
    bench_insert_10k,
    bench_tips_10k,
    bench_roots_10k,
    bench_ancestors_10k,
    bench_descendants_10k,
    bench_wide_dag_tips,
);
criterion_main!(benches);
