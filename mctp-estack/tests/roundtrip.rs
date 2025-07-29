// SPDX-License-Identifier: MIT OR Apache-2.0
/*
 * Copyright (c) 2025 Code Construct
 */

#[allow(unused)]
use log::{debug, error, info, trace, warn};

use mctp::{Eid, MsgType};

use mctp::{AsyncListener, AsyncReqChannel, AsyncRespChannel};
use mctp_estack::config::NUM_RECEIVE;
use mctp_estack::router::{
    Port, PortId, PortLookup, PortTop, RouterAsyncReqChannel,
};
use mctp_estack::{config, Router};

use futures::{select, FutureExt};
use std::collections::VecDeque;
use std::future::Future;

pub mod test_step_executor;
use test_step_executor::{StepExecutor, SubTaskRunner};

fn start_log() {
    let _ = env_logger::Builder::new()
        .filter(None, log::LevelFilter::Trace)
        .is_test(true)
        .try_init();
}

/// Always routes out port 0
#[derive(Default)]
struct DefaultRoute;

impl PortLookup for DefaultRoute {
    fn by_eid(
        &self,
        _eid: Eid,
        _src_port: Option<PortId>,
    ) -> (Option<PortId>, Option<usize>) {
        (Some(PortId(0)), None)
    }
}

const DEFAULT_LOOKUP: DefaultRoute = DefaultRoute;

/// Formats hex plus printable ascii
struct HexFmt<'a>(&'a [u8]);
impl core::fmt::Debug for HexFmt<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:02x?}  ", self.0)?;
        for c in self.0 {
            if c.is_ascii() && !c.is_ascii_control() {
                write!(f, "{}", char::from(*c))?;
            } else {
                write!(f, ".")?;
            }
        }
        Ok(())
    }
}

async fn receive_loop(
    name: &str,
    router: &Router<'_>,
    p: PortId,
    mut port: Port<'_>,
) -> ! {
    loop {
        let (pkt, _eid) = port.outbound().await;
        trace!("rx {name} {:?}", HexFmt(pkt));
        router.inbound(pkt, p).await;
        port.outbound_done();
    }
}

/// Run a loop forwarding packets between routera and routerb.
///
/// The `test` Future runs to completion.
async fn router_loop(routera: &Router<'_>, routerb: &Router<'_>) -> ! {
    let port1 = routera.port(PortId(0)).unwrap();
    let port2 = routerb.port(PortId(0)).unwrap();
    let a = receive_loop("a", routerb, port1.id(), port1);
    let b = receive_loop("b", routera, port2.id(), port2);

    select! {
        _ = a.fuse() => unreachable!(),
        _ = b.fuse() => unreachable!(),
    }
}

fn run<F, R>(routera: &Router<'_>, routerb: &Router<'_>, test: F) -> R
where
    F: Future<Output = R>,
{
    let pktloop = router_loop(routera, routerb);
    smol::block_on(async {
        select! {
            res = test.fuse() => {
                info!("Finished");
                res
            }
            _ = pktloop.fuse() => unreachable!(),
        }
    })
}

fn routers<'r>(
    tops: &'r mut [PortTop],
    lookup1: &'r dyn PortLookup,
    lookup2: &'r dyn PortLookup,
) -> (Router<'r>, Router<'r>) {
    start_log();
    let mut p = tops.iter_mut();
    let mut routera = Router::new(Eid(10), lookup1, 0);
    let mut routerb = Router::new(Eid(20), lookup2, 0);
    routera.add_port(p.next().unwrap()).unwrap();
    routerb.add_port(p.next().unwrap()).unwrap();
    (routera, routerb)
}

/// Simple request/response
#[test]
fn router_requests() {
    let mut tops = [PortTop::new(), PortTop::new()];
    let (routera, routerb) =
        routers(&mut tops, &DEFAULT_LOOKUP, &DEFAULT_LOOKUP);

    run(&routera, &routerb, async {
        let typ = MsgType(0x33);
        let mut buf = [0u8; 1000];

        let mut lista = routera.listener(typ).unwrap();

        let mut reqb = routerb.req(routera.get_eid().await);
        reqb.send(typ, b"first").await.unwrap();
        reqb.send(typ, b"second").await.unwrap();

        // check first request
        let (_t, _ic, payload, _resp) = lista.recv(&mut buf).await.unwrap();
        assert_eq!(payload, b"first");

        // respond only to the second request
        let (_t, _ic, payload, mut resp) = lista.recv(&mut buf).await.unwrap();
        assert_eq!(payload, b"second");
        resp.send(b"reply2").await.unwrap();
        let (_t, _ic, payload) = reqb.recv(&mut buf).await.unwrap();
        assert_eq!(payload, b"reply2");
    });
}

/// Test a requester with tag_noexpire()
#[test]
fn router_noexpire() {
    let mut tops = [PortTop::new(), PortTop::new()];
    let (routera, routerb) =
        routers(&mut tops, &DEFAULT_LOOKUP, &DEFAULT_LOOKUP);

    run(&routera, &routerb, async {
        let typ = MsgType(0x33);
        let mut buf = [0u8; 1000];

        let mut lista = routera.listener(typ).unwrap();
        let mut reqb = routerb.req(routera.get_eid().await);
        reqb.tag_noexpire().unwrap();

        let mut counter = 0;

        // Greater iteration count than tag limit.
        for _ in 0..20 {
            // Request
            for s in 0..config::NUM_RECEIVE {
                let msg = format!("req-{}", counter + s).into_bytes();
                reqb.send(typ, &msg).await.unwrap();
            }

            // Listener receive the request
            let mut resps = VecDeque::new();
            for s in 0..config::NUM_RECEIVE {
                let msg = format!("req-{}", counter + s).into_bytes();
                let (_t, _ic, payload, resp) =
                    lista.recv(&mut buf).await.unwrap();
                assert_eq!(payload, msg);
                resps.push_front(resp);
            }

            // Listener respond
            for s in 0..config::NUM_RECEIVE {
                let msg = format!("resp-{}", counter + s).into_bytes();
                let mut resp = resps.pop_front().unwrap();
                resp.send(&msg).await.unwrap();
            }

            // Check the response
            for s in 0..config::NUM_RECEIVE {
                let msg = format!("resp-{}", counter + s).into_bytes();
                let (_t, _ic, payload) = reqb.recv(&mut buf).await.unwrap();
                assert_eq!(payload, msg);
            }
            counter += config::NUM_RECEIVE;
        }
    });
}

#[test]
fn router_listener_timeout() {
    let mut tops = [PortTop::new(), PortTop::new()];
    let (routera, routerb) =
        routers(&mut tops, &DEFAULT_LOOKUP, &DEFAULT_LOOKUP);

    let mut ex = StepExecutor::default();
    ex.add(router_loop(&routera, &routerb));

    let test = async |sub: SubTaskRunner| {
        let mut now = 0;
        let typ = MsgType(0x33);
        let mut buf = [0u8; 1000];

        let mut lista = routera.listener(typ).unwrap();
        lista.set_timeout(Some(1000));

        let mut reqb = routerb.req(routera.get_eid().await);

        // timed out case
        let recv_task =
            sub.start_until_idle(lista.recv(&mut buf)).await.unwrap();

        // Send the message after the recv timeout has elapsed.
        now += 1000;
        routera.update_time(now).await.unwrap();
        reqb.send(typ, b"late").await.unwrap();

        let r = recv_task.await;
        assert!(matches!(r, Err(mctp::Error::TimedOut)));

        // subsequent recv on the listener receives it
        let (_typ, _ic, payload, _resp) = lista.recv(&mut buf).await.unwrap();
        assert_eq!(payload, b"late");

        // not timed out case
        let recv_task =
            sub.start_until_idle(lista.recv(&mut buf)).await.unwrap();

        // Send the message before the recv timeout has elapsed.
        now += 999;
        routera.update_time(now).await.unwrap();
        reqb.send(typ, b"in the nick of time").await.unwrap();
        let (_typ, _ic, payload, _resp) = recv_task.await.unwrap();
        assert_eq!(payload, b"in the nick of time");
    };
    ex.add(test(ex.sub_runner()));
    ex.until_idle();
}

#[test]
fn router_req_timeout() {
    let mut tops = [PortTop::new(), PortTop::new()];
    let (routera, routerb) =
        routers(&mut tops, &DEFAULT_LOOKUP, &DEFAULT_LOOKUP);

    let mut ex = StepExecutor::default();
    ex.add(router_loop(&routera, &routerb));

    let test = async |sub: SubTaskRunner| {
        let mut now = 0;
        let typ = MsgType(0x33);
        let mut bufa = [0u8; 1000];
        let mut bufb = [0u8; 1000];

        let mut lista = routera.listener(typ).unwrap();

        let mut reqb = routerb.req(routera.get_eid().await);
        reqb.set_timeout(Some(1000));

        info!("timed out case");
        reqb.send(typ, b"req").await.unwrap();
        let (_typ, _ic, _payload, mut resp) =
            lista.recv(&mut bufa).await.unwrap();

        let recv_task =
            sub.start_until_idle(reqb.recv(&mut bufb)).await.unwrap();

        now += 1000;
        routerb.update_time(now).await.unwrap();
        trace!("new now {now}");
        let r = recv_task.await;
        assert!(
            matches!(r, Err(mctp::Error::TimedOut)),
            "no response was sent"
        );

        info!("subsequent recv gets it");
        resp.send(b"later").await.unwrap();
        let (_typ, _ic, payload) = reqb.recv(&mut bufb).await.unwrap();
        assert_eq!(payload, b"later");

        info!("late message");
        reqb.send(typ, b"req").await.unwrap();
        let (_typ, _ic, _payload, mut resp) =
            lista.recv(&mut bufa).await.unwrap();

        let recv_task =
            sub.start_until_idle(reqb.recv(&mut bufb)).await.unwrap();

        now += 1000;
        routerb.update_time(now).await.unwrap();

        // Send the message after the recv timeout has elapsed.
        resp.send(b"late").await.unwrap();

        // Ensure the stack receives it it before recv() runs.
        sub.wait_idle().await;

        let (_typ, _ic, payload) = recv_task.await.unwrap();
        assert_eq!(payload, b"late");

        info!("A new cycle succeeds within timeout.");
        reqb.send(typ, b"req").await.unwrap();
        let (_typ, _ic, _payload, mut resp) =
            lista.recv(&mut bufa).await.unwrap();

        let recv_task =
            sub.start_until_idle(reqb.recv(&mut bufb)).await.unwrap();

        // Before elapsed
        now += 999;
        routerb.update_time(now).await.unwrap();
        resp.send(b"made it").await.unwrap();

        let (_typ, _ic, payload) = recv_task.await.unwrap();
        assert_eq!(payload, b"made it");
    };
    ex.add(test(ex.sub_runner()));
    ex.until_idle();
}

#[test]
fn router_reassembly_timeout() {
    let mut tops = [PortTop::new(), PortTop::new()];
    let (routera, routerb) =
        routers(&mut tops, &DEFAULT_LOOKUP, &DEFAULT_LOOKUP);

    let mut ex = StepExecutor::default();
    ex.add(router_loop(&routera, &routerb));

    let test = async |sub: SubTaskRunner| {
        let mut now = 0;
        let typ = MsgType(0x33);
        let mut bufa = [0u8; 1000];
        let mut bufb = [0u8; 1000];

        // 3000 is within the timeout, 8000 is past it.
        for delay in [3000, 8000] {
            let mut lista = routera.listener(typ).unwrap();

            // B -> A
            let mut reqb = routerb.req(routera.get_eid().await);
            reqb.send(typ, b"test").await.unwrap();
            let (_typ, _ic, _payload, mut resp) =
                lista.recv(&mut bufa).await.unwrap();

            now += delay + 100;
            routerb.update_time(now).await.unwrap();

            sub.wait_idle().await;
            // A -> B
            resp.send(b"response").await.unwrap();

            let r = reqb.recv(&mut bufb).await;
            warn!("delay {delay} r {r:?}");
            // REASSEMBLY_EXPIRY_TIMEOUT
            if delay > 6000 {
                assert!(
                    matches!(r, Err(mctp::Error::TimedOut)),
                    "packet shouldn't be received"
                );
            } else {
                assert!(r.is_ok())
            }
        }
    };
    ex.add(test(ex.sub_runner()));
    ex.until_idle();
}

// Tests that retain()ed messages don't expire.
#[test]
fn router_retain_timeout() {
    let mut tops = [PortTop::new(), PortTop::new()];
    let (routera, routerb) =
        routers(&mut tops, &DEFAULT_LOOKUP, &DEFAULT_LOOKUP);

    let mut ex = StepExecutor::default();
    ex.add(router_loop(&routera, &routerb));

    let test = async |sub: SubTaskRunner| {
        let mut now = 0;
        let typ = MsgType(0x33);
        let mut bufa = [0u8; 1000];
        let mut bufb = [0u8; 1000];

        let mut lista = routera.listener(typ).unwrap();

        let mut reqb = routerb.req(routera.get_eid().await);
        reqb.send(typ, b"req").await.unwrap();
        let (_typ, _ic, _payload, mut resp) =
            lista.recv(&mut bufa).await.unwrap();

        resp.send(b"response").await.unwrap();

        sub.wait_idle().await;
        // routerb should now have retain()ed the received message

        // increment time possibly past reassembly timeout
        now += 100_000;
        routerb.update_time(now).await.unwrap();

        let r = reqb.recv(&mut bufb).await;
        assert!(r.is_ok())
    };
    ex.run_to_completion(test(ex.sub_runner())).unwrap();
}

// Checks that dropping reqchannels when full allows further ones to be created
#[test]
fn router_drop_cleanup() {
    #![allow(clippy::needless_range_loop)]
    let mut tops = [PortTop::new(), PortTop::new()];
    let (routera, routerb) =
        routers(&mut tops, &DEFAULT_LOOKUP, &DEFAULT_LOOKUP);

    let mut ex = StepExecutor::default();
    ex.add(router_loop(&routera, &routerb));

    let test = async |sub: SubTaskRunner| {
        let mut now = 0;
        let typ = MsgType(0x33);
        let mut bufa = [0u8; 1000];
        let mut bufb = [0u8; 1000];

        let mut send = async |n: usize| {
            let mut lista = routera.listener(typ).unwrap();
            let mut reqb = routerb.req(routera.get_eid().await);
            reqb.set_timeout(Some(1000));
            reqb.send(typ, b"req").await.unwrap();

            // Send a response, it will get queued in routerb's Stack reassemblers.
            let (_typ, _ic, _payload, mut resp) =
                lista.recv(&mut bufb).await.unwrap();
            resp.send(&n.to_be_bytes()).await.unwrap();
            reqb
        };

        let mut recv = async |req: &mut RouterAsyncReqChannel| {
            let mut recv_task = sub.start(req.recv(&mut bufa));
            match recv_task.run_until_idle().await {
                // Already completed
                Some(r) => r,
                None => {
                    // Run to completion.
                    // Expire the timeout to avoid hangs
                    now += 2000;
                    routerb.update_time(now).await.unwrap();
                    recv_task.await
                }
            }
            .map(|(_typ, _ic, payload)| payload.to_vec())
        };

        //// Test running out of receivers. Last ones are dropped.
        {
            let mut reqs = Vec::new();
            // Fill all the reassemblers. N+1 would be adequate, N+3 just to see.
            for n in 0..config::NUM_RECEIVE + 3 {
                reqs.push(send(n).await);
            }

            // Ensure they all reached the reassemblers.
            sub.wait_idle().await;

            // Test that the last one is dropped
            for n in 0..config::NUM_RECEIVE + 3 {
                let res = recv(&mut reqs[n]).await;

                if n < config::NUM_RECEIVE {
                    assert_eq!(res.unwrap(), &n.to_be_bytes());
                } else {
                    // Last message is dropped
                    assert!(matches!(res, Err(mctp::Error::TimedOut)));
                }
            }
        }

        //// Test running out of receivers, then drop channels to allow more messages.
        {
            let mut reqs = Vec::new();
            let skip = [2, 5];
            for n in 0..config::NUM_RECEIVE + 3 {
                let r = send(n).await;
                if skip.contains(&n) {
                    // Drop reqs 2 and 5
                    reqs.push(None);
                } else {
                    reqs.push(Some(r));
                };
            }

            // Ensure they all reached the reassemblers.
            sub.wait_idle().await;

            // Test that all the non-dropped ones worked, apart from the last one which was full.
            for n in 0..config::NUM_RECEIVE + 3 {
                trace!("recv {n}");

                let Some(req) = &mut reqs[n] else {
                    assert!(skip.contains(&n));
                    continue;
                };
                assert!(!skip.contains(&n));

                let res = recv(req).await;

                if n == NUM_RECEIVE + 3 - 1 {
                    // Last message is dropped
                    assert!(matches!(res, Err(mctp::Error::TimedOut)));
                } else {
                    assert_eq!(res.unwrap(), &n.to_be_bytes());
                }
            }
        }
    };
    ex.run_to_completion(test(ex.sub_runner())).unwrap();
}
