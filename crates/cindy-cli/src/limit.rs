use std::collections::{BTreeSet, HashMap};

use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::take_while1,
    character::complete::{char, multispace0},
    combinator::map,
    multi::fold,
    sequence::{delimited, preceded},
};

#[derive(Debug, Clone)]
enum Expr<'a> {
    Term(&'a str),
    And(Box<Expr<'a>>, Box<Expr<'a>>),
    Or(Box<Expr<'a>>, Box<Expr<'a>>),
    Not(Box<Expr<'a>>),
}

fn identifier(i: &str) -> IResult<&str, &str> {
    take_while1(|c: char| !matches!(c, '&' | '|' | '!' | '(' | ')') && !c.is_whitespace()).parse(i)
}

fn parens(i: &str) -> IResult<&str, Expr<'_>> {
    delimited(
        (multispace0, char('('), multispace0),
        or_expr,
        (multispace0, char(')')),
    )
    .parse(i)
}

fn atom(i: &str) -> IResult<&str, Expr<'_>> {
    delimited(
        multispace0,
        alt((parens, map(identifier, |s: &str| Expr::Term(s)))),
        multispace0,
    )
    .parse(i)
}

fn not_expr(i: &str) -> IResult<&str, Expr<'_>> {
    alt((
        map(
            preceded((multispace0, char('!'), multispace0), not_expr),
            |e| Expr::Not(Box::new(e)),
        ),
        atom,
    ))
    .parse(i)
}

fn and_expr(i: &str) -> IResult<&str, Expr<'_>> {
    let (i, first) = not_expr(i)?;
    fold(
        0..,
        preceded((multispace0, char('&'), multispace0), not_expr),
        move || first.clone(),
        |acc, rhs| Expr::And(Box::new(acc), Box::new(rhs)),
    )
    .parse(i)
}

fn or_expr(i: &str) -> IResult<&str, Expr<'_>> {
    let (i, first) = and_expr(i)?;
    fold(
        0..,
        preceded((multispace0, char('|'), multispace0), and_expr),
        move || first.clone(),
        |acc, rhs| Expr::Or(Box::new(acc), Box::new(rhs)),
    )
    .parse(i)
}

fn parse(input: &str) -> eyre::Result<Expr<'_>> {
    let (rest, expr) = or_expr(input).map_err(|e| eyre::eyre!("{e:?}"))?;
    let rest = rest.trim();
    if !rest.is_empty() {
        eyre::bail!("trailing input after expression: {rest:?}")
    }
    Ok(expr)
}

type HostSet = BTreeSet<usize>;

struct InventoryIndex<'a> {
    term_to_hosts: HashMap<&'a str, HostSet>,
    all_hosts: HostSet,
}
impl<'a> InventoryIndex<'a> {
    fn new<H, FN, FT>(hosts: &'a [H], name_of: FN, tags_of: FT) -> Self
    where
        FN: Fn(&H) -> &str,
        FT: Fn(&H) -> &[String],
    {
        let mut term_to_hosts: HashMap<&str, HostSet> = HashMap::new();
        let mut all_hosts = HostSet::new();

        for (idx, host) in hosts.iter().enumerate() {
            all_hosts.insert(idx);
            term_to_hosts.entry(name_of(host)).or_default().insert(idx);
            for tag in tags_of(host) {
                term_to_hosts.entry(tag.as_str()).or_default().insert(idx);
            }
        }

        Self {
            term_to_hosts,
            all_hosts,
        }
    }

    /// Every term in `expr` that names neither a host nor a tag —
    /// almost certainly a typo, and worth failing on: an unknown term
    /// silently evaluating to the empty set turns `--limit prdo` into
    /// "deploy nothing, exit 0".
    fn unknown_terms<'e>(&self, expr: &'e Expr) -> Vec<&'e str> {
        match expr {
            Expr::Term(t) => {
                if self.term_to_hosts.contains_key(t) {
                    Vec::new()
                } else {
                    vec![t]
                }
            }
            Expr::And(a, b) | Expr::Or(a, b) => {
                let mut out = self.unknown_terms(a);
                out.extend(self.unknown_terms(b));
                out
            }
            Expr::Not(e) => self.unknown_terms(e),
        }
    }

    fn eval(&self, expr: &Expr) -> HostSet {
        match expr {
            Expr::Term(t) => self.term_to_hosts.get(t).cloned().unwrap_or_default(),
            Expr::And(a, b) => &self.eval(a) & &self.eval(b),
            Expr::Or(a, b) => &self.eval(a) | &self.eval(b),
            Expr::Not(e) => &self.all_hosts - &self.eval(e),
        }
    }
}

pub fn select_indices<H, FN, FT>(
    hosts: &[H],
    limit: Option<&str>,
    name_of: FN,
    tags_of: FT,
) -> eyre::Result<Vec<usize>>
where
    FN: Fn(&H) -> &str,
    FT: Fn(&H) -> &[String],
{
    let Some(expr_src) = limit.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok((0..hosts.len()).collect());
    };

    let expr = parse(expr_src)?;

    let inventory_index = InventoryIndex::new(hosts, name_of, tags_of);
    let unknown = inventory_index.unknown_terms(&expr);
    if !unknown.is_empty() {
        eyre::bail!(
            "--limit term(s) {unknown:?} match no host name or tag in the inventory \
             (typo?)"
        );
    }
    Ok(inventory_index.eval(&expr).into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(name: &'static str, tags: &[&'static str]) -> (String, Vec<String>) {
        (
            name.to_string(),
            tags.iter().map(|s| s.to_string()).collect(),
        )
    }

    fn run(hosts: &[(String, Vec<String>)], limit: Option<&str>) -> Vec<String> {
        let idx = select_indices(hosts, limit, |(n, _)| n.as_str(), |(_, t)| t.as_slice())
            .expect("expected limit to parse");
        idx.into_iter().map(|i| hosts[i].0.clone()).collect()
    }

    #[test]
    fn no_limit_returns_all() {
        let hs = vec![h("a", &[]), h("b", &[])];
        assert_eq!(run(&hs, None), vec!["a", "b"]);
        assert_eq!(run(&hs, Some("")), vec!["a", "b"]);
        assert_eq!(run(&hs, Some("   ")), vec!["a", "b"]);
    }

    #[test]
    fn term_matches_name_or_tag() {
        let hs = vec![h("vyos-01", &["router"]), h("ap-01", &["openwrt"])];
        assert_eq!(run(&hs, Some("vyos-01")), vec!["vyos-01"]);
        assert_eq!(run(&hs, Some("router")), vec!["vyos-01"]);
        assert_eq!(run(&hs, Some("openwrt")), vec!["ap-01"]);
    }

    #[test]
    fn intersection() {
        let hs = vec![
            h("a", &["eu", "openwrt"]),
            h("b", &["eu", "router"]),
            h("c", &["us", "openwrt"]),
        ];
        assert_eq!(run(&hs, Some("eu & openwrt")), vec!["a"]);
        assert_eq!(run(&hs, Some("eu & !openwrt")), vec!["b"]);
    }

    #[test]
    fn union() {
        let hs = vec![h("a", &["router"]), h("b", &["ap"]), h("c", &[])];
        assert_eq!(run(&hs, Some("router | ap")), vec!["a", "b"]);
    }

    #[test]
    fn negation() {
        let hs = vec![h("a", &["router"]), h("b", &["router"]), h("c", &["ap"])];
        assert_eq!(run(&hs, Some("!ap")), vec!["a", "b"]);
        assert_eq!(run(&hs, Some("router & !b")), vec!["a"]);
    }

    #[test]
    fn double_negation() {
        let hs = vec![h("a", &["x"]), h("b", &[])];
        assert_eq!(run(&hs, Some("!!x")), vec!["a"]);
    }

    #[test]
    fn precedence_and_binds_tighter_than_or() {
        let hs = vec![h("a", &["x"]), h("b", &["y", "z"]), h("c", &["y"])];
        assert_eq!(run(&hs, Some("x | y & z")), vec!["a", "b"]);
    }

    #[test]
    fn parens_override_precedence() {
        let hs = vec![
            h("a", &["x", "y"]),
            h("b", &["x", "z"]),
            h("c", &["y", "z"]),
        ];
        assert_eq!(run(&hs, Some("(x | y) & !z")), vec!["a"]);
        assert_eq!(run(&hs, Some("(x | z) & !y")), vec!["b"]);
    }

    #[test]
    fn example_1() {
        let hs = vec![
            h("ap-par", &["eu", "par", "openwrt"]),
            h("ap-prg", &["eu", "prg", "openwrt"]),
            h("ap-lon", &["eu", "lon", "openwrt"]),
            h("ap-nyc", &["us", "nyc", "openwrt"]),
            h("rt-par", &["eu", "par", "router"]),
        ];
        assert_eq!(
            run(&hs, Some("eu & openwrt & !prg")),
            vec!["ap-par", "ap-lon"]
        );
    }

    #[test]
    fn whitespace_optional() {
        let hs = vec![h("a", &["x", "y"]), h("b", &["x"])];
        assert_eq!(run(&hs, Some("x&y")), vec!["a"]);
        assert_eq!(run(&hs, Some(" x  &  y ")), vec!["a"]);
        assert_eq!(run(&hs, Some("!!x|y")), vec!["a", "b"]);
    }

    #[test]
    fn identifier_specials() {
        let hs = vec![h("ap.east.01", &["openwrt"]), h("vyos-01-eu", &["router"])];
        assert_eq!(run(&hs, Some("ap.east.01")), vec!["ap.east.01"]);
        assert_eq!(run(&hs, Some("vyos-01-eu")), vec!["vyos-01-eu"]);
    }
}
