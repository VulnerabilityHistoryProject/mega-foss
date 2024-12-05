[
    {
        '$project': {
            'cve_id': '$cve.CVE_data_meta.ID',
            'cpes': '$configurations.nodes.cpe_match'
        }
    }, {
        '$unwind': '$cpes'
    }, {
        '$project': {
            'cve_id': 1,
            'full_cpe_uri': {
                '$cond': {
                    'if': {
                        '$isArray': '$cpes.cpe23Uri'
                    },
                    'then': {
                        '$arrayElemAt': [
                            '$cpes.cpe23Uri', 0
                        ]
                    },
                    'else': '$cpes.cpe23Uri'
                }
            }
        }
    }, {
        '$project': {
            'cve_id': 1,
            'vendor': {
                '$arrayElemAt': [
                    {
                        '$split': [
                            '$full_cpe_uri', ':'
                        ]
                    }, 3
                ]
            },
            'product': {
                '$arrayElemAt': [
                    {
                        '$split': [
                            '$full_cpe_uri', ':'
                        ]
                    }, 4
                ]
            }
        }
    }, {
        '$unionWith': {
            'coll': 'coll',
            'pipeline': [
                {
                    '$match': {
                        'cve.references.reference_data.url': {
                            '$regex': re.compile(r"^.*github.*commit.*([0-9a-f]{40}).*$")
                        }
                    }
                }, {
                    '$project': {
                        'cve_id': '$cve.CVE_data_meta.ID',
                        'urls': {
                            '$map': {
                                'input': {
                                    '$filter': {
                                        'input': '$cve.references.reference_data.url',
                                        'as': 'url',
                                        'cond': {
                                            '$regexMatch': {
                                                'input': '$$url',
                                                'regex': re.compile(r"^.*github.*commit.*([0-9a-f]{40}).*$")
                                            }
                                        }
                                    }
                                },
                                'as': 'url',
                                'in': {
                                    '$regexFind': {
                                        'input': '$$url',
                                        'regex': re.compile(r"^.*github\\.com\/([^\/]+)\/([^\/]+)")
                                    }
                                }
                            }
                        }
                    }
                }, {
                    '$unwind': '$urls'
                }, {
                    '$project': {
                        'cve_id': 1,
                        'vendor': {
                            '$arrayElemAt': [
                                '$urls.captures', 0
                            ]
                        },
                        'product': {
                            '$arrayElemAt': [
                                '$urls.captures', 1
                            ]
                        }
                    }
                }
            ]
        }
    }, {
        '$group': {
            '_id': {
                'cve_id': '$cve_id',
                'vendor': '$vendor',
                'product': '$product'
            }
        }
    }, {
        '$project': {
            '_id': 0,
            'cve_id': '$_id.cve_id',
            'vendor': '$_id.vendor',
            'product': '$_id.product'
        }
    }
]
