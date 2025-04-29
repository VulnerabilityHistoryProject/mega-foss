[
	{
	  $match: {
		"affected.ranges.type": "GIT"
	  }
	},
	{
	  $project: {
		id: true,
		details: true,
		package: "$affected.package",
		affected: true
	  }
	},
	{
	  $unwind: {
		path: "$affected"
	  }
	},
	{
	  $unwind: {
		path: "$affected.ranges"
	  }
	},
	{
	  $unwind: {
		path: "$affected.ranges.repo"
	  }
	},
	{
	  $project: {
		repo: "$affected.ranges.repo",
		osv_id: "$id"
	  }
	},
	{
	  $group: {
		_id: "$repo",
		osv_ids: {
		  $addToSet: "$osv_id"
		}
	  }
	},
	{
	  $project: {
		repo: "$_id",
		osv_ids: 1,
		osv_ids_size: {
		  $size: "$osv_ids"
		}
	  }
	},
	{
	  $match:
		{
		  osv_ids_size: {
			$gt: 1
		  }
		}
	}
  ]